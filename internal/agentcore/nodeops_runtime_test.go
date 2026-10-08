package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
	"testing"
)

type stubPackageBackend struct {
	listPackages       []protocol.PackageInfo
	listErr            error
	upgradablePackages []backends.UpgradablePackageInfo
	upgradableErr      error
	upgradableCalls    int
	actionResult       backends.PackageActionResult
	actionErr          error
	actionCalls        []stubBackendsPackageActionCall
}

type stubBackendsPackageActionCall struct {
	action   string
	packages []string
}

func (s *stubPackageBackend) ListPackages() ([]protocol.PackageInfo, error) {
	return s.listPackages, s.listErr
}

func (s *stubPackageBackend) ListUpgradablePackages() ([]backends.UpgradablePackageInfo, error) {
	s.upgradableCalls++
	return s.upgradablePackages, s.upgradableErr
}

func (s *stubPackageBackend) PerformAction(action string, packages []string) (backends.PackageActionResult, error) {
	s.actionCalls = append(s.actionCalls, stubBackendsPackageActionCall{
		action:   action,
		packages: append([]string(nil), packages...),
	})
	return s.actionResult, s.actionErr
}

type stubServiceBackend struct {
	listServices []protocol.ServiceInfo
	listErr      error
	actionOutput string
	actionErr    error
	actionCalls  []stubServiceActionCall
}

type stubServiceActionCall struct {
	action  string
	service string
}

func (s *stubServiceBackend) ListServices() ([]protocol.ServiceInfo, error) {
	return s.listServices, s.listErr
}

func (s *stubServiceBackend) PerformAction(action, service string) (string, error) {
	s.actionCalls = append(s.actionCalls, stubServiceActionCall{
		action:  action,
		service: service,
	})
	return s.actionOutput, s.actionErr
}

type stubLogBackend struct {
	entries []protocol.LogStreamData
	err     error
	reqs    []protocol.JournalQueryData
}

func (s *stubLogBackend) QueryEntries(req protocol.JournalQueryData) ([]protocol.LogStreamData, error) {
	s.reqs = append(s.reqs, req)
	return s.entries, s.err
}

func (s *stubLogBackend) StreamEntries(_ context.Context, _ func(protocol.LogStreamData)) error {
	return nil
}

func TestProcessManagerHandleProcessListSortsLimitsAndReportsErrors(t *testing.T) {
	originalCollectProcesses := system.CollectProcessesFn
	t.Cleanup(func() {
		system.CollectProcessesFn = originalCollectProcesses
	})

	t.Run("success", func(t *testing.T) {
		system.CollectProcessesFn = func() ([]protocol.ProcessInfo, error) {
			return []protocol.ProcessInfo{
				{PID: 101, Name: "alpha", CPUPct: 10, MemPct: 25},
				{PID: 102, Name: "beta", CPUPct: 40, MemPct: 5},
				{PID: 103, Name: "gamma", CPUPct: 1, MemPct: 90},
			}, nil
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := system.NewProcessManager()
		manager.HandleProcessList(transport, protocol.Message{
			Type: protocol.MsgProcessList,
			Data: mustMarshalDesktopRuntime(t, protocol.ProcessListData{
				RequestID: "req-process-list",
				SortBy:    "memory",
				Limit:     2,
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgProcessListed {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgProcessListed)
		}

		var listed protocol.ProcessListedData
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode process listed payload: %v", err)
		}
		if listed.RequestID != "req-process-list" {
			t.Fatalf("request_id=%q, want req-process-list", listed.RequestID)
		}
		if listed.Error != "" {
			t.Fatalf("unexpected error %q", listed.Error)
		}
		if got, want := len(listed.Processes), 2; got != want {
			t.Fatalf("len(processes)=%d, want %d", got, want)
		}
		if listed.Processes[0].PID != 103 || listed.Processes[1].PID != 101 {
			t.Fatalf("unexpected process order %+v", listed.Processes)
		}
	})

	t.Run("error", func(t *testing.T) {
		system.CollectProcessesFn = func() ([]protocol.ProcessInfo, error) {
			return nil, errors.New("ps failed")
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := system.NewProcessManager()
		manager.HandleProcessList(transport, protocol.Message{
			Type: protocol.MsgProcessList,
			Data: mustMarshalDesktopRuntime(t, protocol.ProcessListData{RequestID: "req-process-error"}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		var listed protocol.ProcessListedData
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode process listed payload: %v", err)
		}
		if listed.RequestID != "req-process-error" {
			t.Fatalf("request_id=%q, want req-process-error", listed.RequestID)
		}
		if listed.Error != "ps failed" {
			t.Fatalf("error=%q, want ps failed", listed.Error)
		}
	})
}

func TestProcessManagerHandleProcessKillGuardsAndReportsResults(t *testing.T) {
	originalKillProcess := system.KillProcessFn
	t.Cleanup(func() {
		system.KillProcessFn = originalKillProcess
	})

	t.Run("rejects pid one", func(t *testing.T) {
		killCalled := false
		system.KillProcessFn = func(int, string) error {
			killCalled = true
			return nil
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := system.NewProcessManager()
		manager.HandleProcessKill(transport, protocol.Message{
			Type: protocol.MsgProcessKill,
			ID:   "req-process-kill-guard",
			Data: mustMarshalDesktopRuntime(t, protocol.ProcessKillData{PID: 1}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgProcessKillResult {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgProcessKillResult)
		}
		if msg.ID != "req-process-kill-guard" {
			t.Fatalf("message id=%q, want req-process-kill-guard", msg.ID)
		}

		var result protocol.ProcessKillResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode process kill result: %v", err)
		}
		if result.Error != "refusing to signal PID <= 1" {
			t.Fatalf("error=%q, want refusing to signal PID <= 1", result.Error)
		}
		if killCalled {
			t.Fatal("expected killProcess not to be called")
		}
	})

	t.Run("success", func(t *testing.T) {
		calledPID := 0
		calledSignal := ""
		system.KillProcessFn = func(pid int, signal string) error {
			calledPID = pid
			calledSignal = signal
			return nil
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := system.NewProcessManager()
		manager.HandleProcessKill(transport, protocol.Message{
			Type: protocol.MsgProcessKill,
			ID:   "req-process-kill-success",
			Data: mustMarshalDesktopRuntime(t, protocol.ProcessKillData{PID: 42, Signal: "SIGKILL"}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.ID != "req-process-kill-success" {
			t.Fatalf("message id=%q, want req-process-kill-success", msg.ID)
		}
		var result protocol.ProcessKillResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode process kill result: %v", err)
		}
		if !result.Success || result.PID != 42 {
			t.Fatalf("unexpected kill result %+v", result)
		}
		if calledPID != 42 || calledSignal != "SIGKILL" {
			t.Fatalf("kill called with pid=%d signal=%q", calledPID, calledSignal)
		}
	})

	t.Run("error", func(t *testing.T) {
		system.KillProcessFn = func(int, string) error {
			return errors.New("permission denied")
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := system.NewProcessManager()
		manager.HandleProcessKill(transport, protocol.Message{
			Type: protocol.MsgProcessKill,
			ID:   "req-process-kill-error",
			Data: mustMarshalDesktopRuntime(t, protocol.ProcessKillData{PID: 77, Signal: "SIGTERM"}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.ID != "req-process-kill-error" {
			t.Fatalf("message id=%q, want req-process-kill-error", msg.ID)
		}
		var result protocol.ProcessKillResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode process kill result: %v", err)
		}
		if result.Error != "permission denied" {
			t.Fatalf("error=%q, want permission denied", result.Error)
		}
	})
}
