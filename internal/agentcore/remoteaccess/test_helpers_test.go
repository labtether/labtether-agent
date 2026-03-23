package remoteaccess

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// mockTransport implements MessageSender for tests.
type mockTransport struct {
	mu       sync.Mutex
	messages chan protocol.Message
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		messages: make(chan protocol.Message, 64),
	}
}

func (m *mockTransport) Send(msg protocol.Message) error {
	m.messages <- msg
	return nil
}

func newDesktopRuntimeTransport(t *testing.T) (MessageSender, <-chan protocol.Message, func()) {
	t.Helper()
	mt := newMockTransport()
	return mt, mt.messages, func() {}
}

func readDesktopRuntimeMessage(t *testing.T, messages <-chan protocol.Message) protocol.Message {
	t.Helper()
	select {
	case msg := <-messages:
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for desktop runtime message")
		return protocol.Message{}
	}
}

func mustMarshalDesktopRuntime(t *testing.T, payload any) []byte {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return data
}

func readWebRTCStopped(t *testing.T, messages <-chan protocol.Message) protocol.WebRTCStoppedData {
	t.Helper()

	msg := readDesktopRuntimeMessage(t, messages)
	if msg.Type != protocol.MsgWebRTCStopped {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgWebRTCStopped)
	}

	var stopped protocol.WebRTCStoppedData
	if err := json.Unmarshal(msg.Data, &stopped); err != nil {
		t.Fatalf("decode webrtc stopped payload: %v", err)
	}
	return stopped
}

func ContainsEnvValue(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}

// mockSettingsProvider implements SettingsProvider for tests.
type mockSettingsProvider struct {
	settings map[string]string
}

func (m *mockSettingsProvider) ReportedAgentSettings() map[string]string {
	if m.settings == nil {
		return map[string]string{}
	}
	return m.settings
}

// newDisabledWebRTCSettings returns a SettingsProvider that reports WebRTC disabled.
func newDisabledWebRTCSettings() SettingsProvider {
	return &mockSettingsProvider{settings: map[string]string{"webrtc_enabled": "false"}}
}
