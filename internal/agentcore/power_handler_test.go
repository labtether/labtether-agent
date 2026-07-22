package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type fakePowerSender struct {
	assetID string
	mu      sync.Mutex
	sent    []protocol.Message
}

func (s *fakePowerSender) AssetID() string { return s.assetID }

func (s *fakePowerSender) Send(msg protocol.Message) error {
	s.mu.Lock()
	s.sent = append(s.sent, msg)
	s.mu.Unlock()
	return nil
}

func (s *fakePowerSender) result(t *testing.T) powerResultData {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(s.sent))
	}
	if s.sent[0].Type != msgPowerResult {
		t.Fatalf("message type=%q, want %q", s.sent[0].Type, msgPowerResult)
	}
	var result powerResultData
	if err := json.Unmarshal(s.sent[0].Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if s.sent[0].ID != result.RequestID {
		t.Fatalf("envelope id=%q payload request=%q", s.sent[0].ID, result.RequestID)
	}
	return result
}

type fakePowerBackend struct {
	supported bool
	execute   func(context.Context, powerAction) error
	mu        sync.Mutex
	calls     []powerAction
}

func (b *fakePowerBackend) Supported(powerAction) bool { return b.supported }

func (b *fakePowerBackend) Execute(ctx context.Context, action powerAction) error {
	b.mu.Lock()
	b.calls = append(b.calls, action)
	b.mu.Unlock()
	if b.execute != nil {
		return b.execute(ctx, action)
	}
	return nil
}

func validPowerMessage(t *testing.T, assetID string, action powerAction) protocol.Message {
	t.Helper()
	payload := powerActionData{RequestID: "power-1", AssetID: assetID, Action: action}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode action: %v", err)
	}
	return protocol.Message{Type: msgPowerAction, ID: payload.RequestID, Data: raw}
}

func TestHandlePowerActionAcceptedUsesInjectedBackend(t *testing.T) {
	sender := &fakePowerSender{assetID: "node-1"}
	backend := &fakePowerBackend{supported: true}
	handlePowerAction(context.Background(), sender, validPowerMessage(t, "node-1", powerActionReboot), backend)

	result := sender.result(t)
	if result.Status != powerResultAccepted || result.Code != "" || result.Action != powerActionReboot || result.AssetID != "node-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !reflect.DeepEqual(backend.calls, []powerAction{powerActionReboot}) {
		t.Fatalf("backend calls=%v", backend.calls)
	}
}

func TestHandlePowerActionRejectsBeforeBackend(t *testing.T) {
	tests := []struct {
		name     string
		assetID  string
		message  protocol.Message
		wantCode powerResultCode
	}{
		{
			name:     "asset mismatch",
			assetID:  "node-2",
			message:  validPowerMessage(t, "node-1", powerActionShutdown),
			wantCode: powerResultCodeAssetMismatch,
		},
		{
			name:    "request id mismatch",
			assetID: "node-1",
			message: func() protocol.Message {
				msg := validPowerMessage(t, "node-1", powerActionReboot)
				msg.ID = "power-other"
				return msg
			}(),
			wantCode: powerResultCodeInvalidRequest,
		},
		{
			name:     "unknown field",
			assetID:  "node-1",
			message:  protocol.Message{Type: msgPowerAction, ID: "power-1", Data: []byte(`{"request_id":"power-1","asset_id":"node-1","action":"reboot","command":"rm -rf /"}`)},
			wantCode: powerResultCodeInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakePowerSender{assetID: tc.assetID}
			backend := &fakePowerBackend{supported: true}
			handlePowerAction(context.Background(), sender, tc.message, backend)
			result := sender.result(t)
			if result.Status != powerResultRejected || result.Code != tc.wantCode {
				t.Fatalf("unexpected result: %+v", result)
			}
			if len(backend.calls) != 0 {
				t.Fatalf("backend invoked for rejected request: %v", backend.calls)
			}
		})
	}
}

func TestHandlePowerActionUnsupportedFailureAndTimeout(t *testing.T) {
	tests := []struct {
		name       string
		backend    *fakePowerBackend
		timeout    time.Duration
		wantStatus powerResultStatus
		wantCode   powerResultCode
	}{
		{
			name:       "unsupported",
			backend:    &fakePowerBackend{},
			timeout:    time.Second,
			wantStatus: powerResultUnsupported,
			wantCode:   powerResultCodeUnsupportedPlatform,
		},
		{
			name: "execution failure",
			backend: &fakePowerBackend{supported: true, execute: func(context.Context, powerAction) error {
				return errors.New("permission denied")
			}},
			timeout:    time.Second,
			wantStatus: powerResultFailed,
			wantCode:   powerResultCodeExecutionFailed,
		},
		{
			name: "execution timeout",
			backend: &fakePowerBackend{supported: true, execute: func(ctx context.Context, _ powerAction) error {
				<-ctx.Done()
				return ctx.Err()
			}},
			timeout:    5 * time.Millisecond,
			wantStatus: powerResultFailed,
			wantCode:   powerResultCodeExecutionTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakePowerSender{assetID: "node-1"}
			handlePowerActionWithTimeout(context.Background(), sender, validPowerMessage(t, "node-1", powerActionShutdown), tc.backend, tc.timeout)
			result := sender.result(t)
			if result.Status != tc.wantStatus || result.Code != tc.wantCode {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestSendPowerRejectionForCapabilityAndBusy(t *testing.T) {
	for _, code := range []powerResultCode{powerResultCodeCapabilityDenied, powerResultCodeBusy} {
		sender := &fakePowerSender{assetID: "node-1"}
		sendPowerRejectionForMessage(sender, validPowerMessage(t, "node-1", powerActionReboot), code, "request rejected")
		result := sender.result(t)
		if result.Status != powerResultRejected || result.Code != code {
			t.Fatalf("code=%q result=%+v", code, result)
		}
	}
}

type recordingPowerRunner struct {
	executable string
	args       []string
	err        error
}

func (r *recordingPowerRunner) Run(_ context.Context, executable string, args ...string) error {
	r.executable = executable
	r.args = append([]string(nil), args...)
	return r.err
}

func TestPowerCommandAllowlistForAllSupportedPlatforms(t *testing.T) {
	tests := []struct {
		name       string
		goos       string
		systemRoot string
		action     powerAction
		executable string
		args       []string
	}{
		{"linux reboot", "linux", "", powerActionReboot, "/usr/bin/systemctl", []string{"reboot", "--no-wall"}},
		{"linux shutdown", "linux", "", powerActionShutdown, "/usr/bin/systemctl", []string{"poweroff", "--no-wall"}},
		{"mac reboot", "darwin", "", powerActionReboot, "/sbin/shutdown", []string{"-r", "now"}},
		{"mac shutdown", "darwin", "", powerActionShutdown, "/sbin/shutdown", []string{"-h", "now"}},
		{"freebsd reboot", "freebsd", "", powerActionReboot, "/sbin/shutdown", []string{"-r", "now"}},
		{"freebsd shutdown", "freebsd", "", powerActionShutdown, "/sbin/shutdown", []string{"-p", "now"}},
		{"windows reboot", "windows", `D:\Windows`, powerActionReboot, `D:\Windows\System32\shutdown.exe`, []string{"/r", "/t", "5", "/d", "p:4:1", "/c", "LabTether requested reboot"}},
		{"windows shutdown", "windows", `C:\Windows`, powerActionShutdown, `C:\Windows\System32\shutdown.exe`, []string{"/s", "/t", "5", "/d", "p:4:1", "/c", "LabTether requested shutdown"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := powerCommandForPlatform(tc.goos, tc.systemRoot, tc.action)
			if err != nil {
				t.Fatalf("command: %v", err)
			}
			if spec.executable != tc.executable || !reflect.DeepEqual(spec.args, tc.args) {
				t.Fatalf("got executable=%q args=%v, want %q %v", spec.executable, spec.args, tc.executable, tc.args)
			}
		})
	}

	for _, tc := range []struct {
		goos       string
		systemRoot string
		action     powerAction
	}{
		{"plan9", "", powerActionReboot},
		{"linux", "", "hibernate"},
		{"windows", `..\Windows`, powerActionShutdown},
	} {
		if _, err := powerCommandForPlatform(tc.goos, tc.systemRoot, tc.action); !errors.Is(err, errPowerUnsupported) {
			t.Fatalf("expected unsupported for %+v, got %v", tc, err)
		}
	}
}

func TestCommandPowerBackendUsesOnlyFixedSpec(t *testing.T) {
	runner := &recordingPowerRunner{}
	backend := &commandPowerBackend{goos: "linux", runner: runner}
	if err := backend.Execute(context.Background(), powerActionShutdown); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if runner.executable != "/usr/bin/systemctl" || !reflect.DeepEqual(runner.args, []string{"poweroff", "--no-wall"}) {
		t.Fatalf("runner got %q %v", runner.executable, runner.args)
	}
}

func TestPowerActionRequiresPowerCapability(t *testing.T) {
	got := requiredCapabilitiesForMessage(msgPowerAction)
	want := []string{"agent.power", "power.manage", "agent.operations"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities=%v, want %v", got, want)
	}
}
