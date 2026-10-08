package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/protocol"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestJournalManagerHandleJournalQueryReturnsEntriesAndErrors(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubLogBackend{
			entries: []protocol.LogStreamData{{
				Timestamp: "2026-03-08T12:00:00Z",
				Level:     "error",
				Message:   "denied",
				Source:    "sshd",
			}},
		}
		manager := &backends.JournalManager{Backend: backend}
		manager.HandleJournalQuery(transport, protocol.Message{
			Type: protocol.MsgJournalQuery,
			Data: mustMarshalDesktopRuntime(t, protocol.JournalQueryData{
				RequestID: "req-journal",
				Unit:      "sshd.service",
				Limit:     50,
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgJournalEntries {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgJournalEntries)
		}
		var listed protocol.JournalEntriesData
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode journal entries payload: %v", err)
		}
		if listed.RequestID != "req-journal" || len(listed.Entries) != 1 || listed.Entries[0].Source != "sshd" {
			t.Fatalf("unexpected journal response %+v", listed)
		}
		if got := backend.reqs; len(got) != 1 || got[0].Unit != "sshd.service" || got[0].Limit != 50 {
			t.Fatalf("backend requests=%+v", got)
		}
	})

	t.Run("error", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubLogBackend{err: errors.New("journalctl unavailable")}
		manager := &backends.JournalManager{Backend: backend}
		manager.HandleJournalQuery(transport, protocol.Message{
			Type: protocol.MsgJournalQuery,
			Data: mustMarshalDesktopRuntime(t, protocol.JournalQueryData{RequestID: "req-journal-error"}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		var listed protocol.JournalEntriesData
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode journal entries payload: %v", err)
		}
		if listed.Error != "journalctl unavailable" {
			t.Fatalf("error=%q, want journalctl unavailable", listed.Error)
		}
	})
}

func TestLinuxLogBackendQueryEntriesUsesFiltersAndParsesResults(t *testing.T) {
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is required for journal query test")
	}

	originalLookPath := backends.JournalLookPath
	originalNewCommand := backends.NewJournalCommandContext
	originalTimeout := backends.JournalQueryTimeout
	t.Cleanup(func() {
		backends.JournalLookPath = originalLookPath
		backends.NewJournalCommandContext = originalNewCommand
		backends.JournalQueryTimeout = originalTimeout
	})

	backends.JournalLookPath = func(name string) (string, error) {
		if name != "journalctl" {
			t.Fatalf("lookPath called with %q", name)
		}
		return "/usr/bin/journalctl", nil
	}

	var capturedName string
	var capturedArgs []string
	backends.NewJournalCommandContext = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		capturedName = name
		capturedArgs = append([]string(nil), args...)
		script := `printf '%s\n' '{"__REALTIME_TIMESTAMP":"1700000000000000","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"3","MESSAGE":"denied password","SYSLOG_IDENTIFIER":"sshd"}' '{"__REALTIME_TIMESTAMP":"1700000001000000","_SYSTEMD_UNIT":"cron.service","PRIORITY":"6","MESSAGE":"job complete"}'`
		return exec.CommandContext(ctx, shellPath, "-c", script), nil
	}
	backends.JournalQueryTimeout = 2 * time.Second

	entries, err := backends.LinuxLogBackend{}.QueryEntries(protocol.JournalQueryData{
		RequestID: "req-journal-query",
		Since:     "1h ago",
		Until:     "now",
		Unit:      "sshd.service",
		Priority:  "err",
		Search:    "denied",
		Limit:     5,
	})
	if err != nil {
		t.Fatalf("QueryEntries returned error: %v", err)
	}
	if capturedName != "journalctl" {
		t.Fatalf("command name=%q, want journalctl", capturedName)
	}
	if got, want := capturedArgs, []string{
		"--no-pager",
		"--output=json",
		"-n", "5",
		"-r",
		"--since", "1h ago",
		"--until", "now",
		"-u", "sshd.service",
		"-p", "err",
		"--grep", "denied",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%v, want %v", got, want)
	}
	if got, want := len(entries), 2; got != want {
		t.Fatalf("len(entries)=%d, want %d", got, want)
	}
	if entries[0].Source != "sshd" || entries[0].Level != "error" || entries[0].Message != "denied password" {
		t.Fatalf("unexpected first entry %+v", entries[0])
	}
	if entries[1].Source != "cron" || entries[1].Level != "info" || entries[1].Message != "job complete" {
		t.Fatalf("unexpected second entry %+v", entries[1])
	}
}

func TestLinuxLogBackendQueryEntriesTimesOut(t *testing.T) {
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is required for journal timeout test")
	}

	originalLookPath := backends.JournalLookPath
	originalNewCommand := backends.NewJournalCommandContext
	originalTimeout := backends.JournalQueryTimeout
	t.Cleanup(func() {
		backends.JournalLookPath = originalLookPath
		backends.NewJournalCommandContext = originalNewCommand
		backends.JournalQueryTimeout = originalTimeout
	})

	backends.JournalLookPath = func(string) (string, error) { return "/usr/bin/journalctl", nil }
	backends.NewJournalCommandContext = func(ctx context.Context, _ string, _ ...string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, shellPath, "-c", "sleep 1"), nil
	}
	backends.JournalQueryTimeout = 20 * time.Millisecond

	_, err = backends.LinuxLogBackend{}.QueryEntries(protocol.JournalQueryData{Limit: 10})
	if err == nil || err.Error() != "journalctl query timed out" {
		t.Fatalf("error=%v, want journalctl query timed out", err)
	}
}
