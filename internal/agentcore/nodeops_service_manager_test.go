package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/protocol"
	"reflect"
	"strings"
	"testing"
)

func TestServiceManagerHandleServiceListAndAction(t *testing.T) {
	t.Run("list success and error", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		successBackend := &stubServiceBackend{
			listServices: []protocol.ServiceInfo{{
				Name:        "sshd",
				Description: "OpenSSH Daemon",
				ActiveState: "active",
				SubState:    "running",
				Enabled:     "enabled",
				LoadState:   "loaded",
			}},
		}
		manager := &backends.ServiceManager{Backend: successBackend}
		manager.HandleServiceList(transport, protocol.Message{
			Type: protocol.MsgServiceList,
			Data: mustMarshalDesktopRuntime(t, protocol.ServiceListData{RequestID: "req-service-list"}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgServiceListed {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgServiceListed)
		}
		var listed protocol.ServiceListedData
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode service listed payload: %v", err)
		}
		if listed.RequestID != "req-service-list" || len(listed.Services) != 1 || listed.Services[0].Name != "sshd" {
			t.Fatalf("unexpected service list %+v", listed)
		}

		errorBackend := &stubServiceBackend{listErr: errors.New("systemctl failed")}
		manager = &backends.ServiceManager{Backend: errorBackend}
		manager.HandleServiceList(transport, protocol.Message{
			Type: protocol.MsgServiceList,
			Data: mustMarshalDesktopRuntime(t, protocol.ServiceListData{RequestID: "req-service-error"}),
		})

		msg = readDesktopRuntimeMessage(t, messages)
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode service listed payload: %v", err)
		}
		if listed.Error != "systemctl failed" {
			t.Fatalf("error=%q, want systemctl failed", listed.Error)
		}
	})

	t.Run("action success and validation", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubServiceBackend{actionOutput: "restarted"}
		manager := &backends.ServiceManager{Backend: backend}
		manager.HandleServiceAction(transport, protocol.Message{
			Type: protocol.MsgServiceAction,
			Data: mustMarshalDesktopRuntime(t, protocol.ServiceActionData{
				RequestID: "req-service-action",
				Service:   "sshd",
				Action:    "restart",
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgServiceResult {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgServiceResult)
		}
		var result protocol.ServiceResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode service result payload: %v", err)
		}
		if !result.OK || result.Output != "restarted" {
			t.Fatalf("unexpected service result %+v", result)
		}
		if got, want := backend.actionCalls, []stubServiceActionCall{{action: "restart", service: "sshd"}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("backend calls=%#v, want %#v", got, want)
		}

		manager.HandleServiceAction(transport, protocol.Message{
			Type: protocol.MsgServiceAction,
			Data: mustMarshalDesktopRuntime(t, protocol.ServiceActionData{
				RequestID: "req-service-invalid",
				Service:   "sshd",
				Action:    "reload",
			}),
		})
		msg = readDesktopRuntimeMessage(t, messages)
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode service result payload: %v", err)
		}
		if !strings.Contains(result.Error, "invalid action") {
			t.Fatalf("error=%q, want invalid action", result.Error)
		}
	})
}

func TestLinuxServiceBackendListServicesParsesSystemctlOutput(t *testing.T) {
	originalRunCommand := backends.RunLinuxServiceCommand
	t.Cleanup(func() {
		backends.RunLinuxServiceCommand = originalRunCommand
	})

	backends.RunLinuxServiceCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("command name=%q, want systemctl", name)
		}
		switch args[0] {
		case "list-unit-files":
			return []byte("sshd.service enabled\ncron.service disabled\n"), nil
		case "list-units":
			return []byte(strings.Join([]string{
				"sshd.service loaded active running OpenSSH Daemon",
				"cron.service loaded inactive dead Cron Daemon",
			}, "\n")), nil
		default:
			t.Fatalf("unexpected systemctl args=%v", args)
			return nil, nil
		}
	}

	services, err := backends.LinuxServiceBackend{}.ListServices()
	if err != nil {
		t.Fatalf("ListServices returned error: %v", err)
	}
	if got, want := len(services), 2; got != want {
		t.Fatalf("len(services)=%d, want %d", got, want)
	}
	if services[0].Name != "sshd" || services[0].Enabled != "enabled" || services[0].Description != "OpenSSH Daemon" {
		t.Fatalf("unexpected first service %+v", services[0])
	}
	if services[1].Name != "cron" || services[1].Enabled != "disabled" || services[1].ActiveState != "inactive" {
		t.Fatalf("unexpected second service %+v", services[1])
	}
}

func TestLinuxServiceBackendListServicesReportsNonSystemdFailure(t *testing.T) {
	originalRunCommand := backends.RunLinuxServiceCommand
	t.Cleanup(func() {
		backends.RunLinuxServiceCommand = originalRunCommand
	})

	backends.RunLinuxServiceCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "list-unit-files":
			return nil, errors.New("System has not been booted with systemd as init system")
		case "list-units":
			return nil, errors.New("System has not been booted with systemd as init system")
		default:
			t.Fatalf("unexpected systemctl args=%v", args)
			return nil, nil
		}
	}

	_, err := backends.LinuxServiceBackend{}.ListServices()
	if err == nil || !strings.Contains(err.Error(), "systemctl list-units") {
		t.Fatalf("error=%v, want systemctl list-units failure", err)
	}
}

func TestLinuxServiceBackendPerformActionReturnsTimeoutWithOutput(t *testing.T) {
	originalRunCommand := backends.RunLinuxServiceCommand
	t.Cleanup(func() {
		backends.RunLinuxServiceCommand = originalRunCommand
	})

	backends.RunLinuxServiceCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" || len(args) != 2 || args[0] != "restart" || args[1] != "sshd" {
			t.Fatalf("unexpected systemctl invocation %q %v", name, args)
		}
		return []byte("stopping sshd"), context.DeadlineExceeded
	}

	output, err := backends.LinuxServiceBackend{}.PerformAction("restart", "sshd")
	if err == nil || err.Error() != "systemctl timed out" {
		t.Fatalf("error=%v, want systemctl timed out", err)
	}
	if output != "stopping sshd" {
		t.Fatalf("output=%q, want stopping sshd", output)
	}
}
