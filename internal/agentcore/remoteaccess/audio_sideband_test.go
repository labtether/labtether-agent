package remoteaccess

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/labtether/protocol"
)

type audioCaptureMessageSender struct {
	messages []protocol.Message
}

func (s *audioCaptureMessageSender) Send(message protocol.Message) error {
	s.messages = append(s.messages, message)
	return nil
}

func TestAudioSidebandManagerRejectsSessionAboveLimit(t *testing.T) {
	manager := NewAudioSidebandManager()
	defer manager.CloseAll()
	for index := 0; index < MaxAudioSidebandSessions; index++ {
		_, cancel := context.WithCancel(context.Background())
		manager.Sessions[string(rune('a'+index))] = &AudioSidebandSession{cancel: cancel}
	}
	transport := &audioCaptureMessageSender{}
	payload, err := json.Marshal(protocol.DesktopAudioStartData{SessionID: "overflow"})
	if err != nil {
		t.Fatalf("marshal audio start: %v", err)
	}

	manager.HandleAudioStart(transport, protocol.Message{Type: protocol.MsgDesktopAudioStart, Data: payload})

	if len(manager.Sessions) != MaxAudioSidebandSessions {
		t.Fatalf("audio session count = %d, want %d", len(manager.Sessions), MaxAudioSidebandSessions)
	}
	if len(transport.messages) != 1 {
		t.Fatalf("state messages = %d, want 1", len(transport.messages))
	}
	var state protocol.DesktopAudioStateData
	if err := json.Unmarshal(transport.messages[0].Data, &state); err != nil {
		t.Fatalf("decode audio state: %v", err)
	}
	if state.State != "unavailable" || !strings.Contains(state.Error, "too many") {
		t.Fatalf("unexpected audio state: %+v", state)
	}
}

func TestAudioSidebandManagerRejectsDuplicateSessionID(t *testing.T) {
	manager := NewAudioSidebandManager()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	existing := &AudioSidebandSession{cancel: cancel}
	manager.Sessions["duplicate"] = existing
	transport := &audioCaptureMessageSender{}
	payload, err := json.Marshal(protocol.DesktopAudioStartData{SessionID: " duplicate "})
	if err != nil {
		t.Fatalf("marshal audio start: %v", err)
	}

	manager.HandleAudioStart(transport, protocol.Message{Type: protocol.MsgDesktopAudioStart, Data: payload})

	if manager.Sessions["duplicate"] != existing {
		t.Fatal("duplicate start replaced the active audio session")
	}
	if len(manager.Sessions) != 1 {
		t.Fatalf("audio session count = %d, want 1", len(manager.Sessions))
	}
	if len(transport.messages) != 1 {
		t.Fatalf("state messages = %d, want 1", len(transport.messages))
	}
	var state protocol.DesktopAudioStateData
	if err := json.Unmarshal(transport.messages[0].Data, &state); err != nil {
		t.Fatalf("decode audio state: %v", err)
	}
	if state.SessionID != "duplicate" || state.State != "unavailable" || !strings.Contains(state.Error, "already exists") {
		t.Fatalf("unexpected duplicate audio state: %+v", state)
	}
}

func TestAudioSidebandManagerStaleCaptureCannotRemoveReplacement(t *testing.T) {
	manager := NewAudioSidebandManager()
	_, oldCancel := context.WithCancel(context.Background())
	oldSession := &AudioSidebandSession{cancel: oldCancel}
	_, replacementCancel := context.WithCancel(context.Background())
	replacement := &AudioSidebandSession{cancel: replacementCancel}
	manager.Sessions["same-id"] = replacement
	transport := &audioCaptureMessageSender{}

	if manager.sendStateIfCurrent(transport, "same-id", oldSession, "stopped", "", true) {
		t.Fatal("stale capture sent a replacement state message")
	}

	if manager.Sessions["same-id"] != replacement {
		t.Fatal("stale capture removed replacement audio session")
	}
	if len(transport.messages) != 0 {
		t.Fatalf("stale capture sent %d messages", len(transport.messages))
	}
}
