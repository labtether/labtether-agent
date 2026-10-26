package sysconfig

import (
	"encoding/json"
	"testing"

	"github.com/labtether/protocol"
)

type clipboardTestSender struct{ message protocol.Message }

func (s *clipboardTestSender) Send(message protocol.Message) error { s.message = message; return nil }

func TestClipboardUnsupportedFormatDoesNotTouchClipboard(t *testing.T) {
	read, text, image := ClipboardRead, ClipboardWriteText, ClipboardWriteImage
	t.Cleanup(func() { ClipboardRead, ClipboardWriteText, ClipboardWriteImage = read, text, image })
	ClipboardRead = func(string) (string, string, error) { t.Fatal("unsupported format read clipboard"); return "", "", nil }
	ClipboardWriteText = func(string) error { t.Fatal("unsupported format overwrote text clipboard"); return nil }
	ClipboardWriteImage = func(string) error { t.Fatal("unsupported format overwrote image clipboard"); return nil }
	manager := NewClipboardManager()
	sender := &clipboardTestSender{}
	manager.HandleClipboardGet(sender, protocol.Message{Data: []byte(`{"request_id":"read","format":"text/html"}`)})
	var data protocol.ClipboardDataPayload
	if err := json.Unmarshal(sender.message.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Error == "" || data.RequestID != "read" {
		t.Fatalf("missing read error: %+v", data)
	}
	manager.HandleClipboardSet(sender, protocol.Message{Data: []byte(`{"request_id":"write","format":"text/html","text":"wrong format"}`)})
	var ack protocol.ClipboardSetAckData
	if err := json.Unmarshal(sender.message.Data, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.OK || ack.Error == "" || ack.RequestID != "write" {
		t.Fatalf("missing write error: %+v", ack)
	}
}

func TestClipboardTextAliasPreservesAllText(t *testing.T) {
	read, write := ClipboardRead, ClipboardWriteText
	t.Cleanup(func() { ClipboardRead, ClipboardWriteText = read, write })
	const exact = "  café 🎉\r\n\n"
	ClipboardRead = func(format string) (string, string, error) {
		if format != "text" {
			t.Fatalf("wrong read format %q", format)
		}
		return exact, "", nil
	}
	ClipboardWriteText = func(text string) error {
		if text != exact {
			t.Fatalf("clipboard bytes changed: %q", text)
		}
		return nil
	}
	manager := NewClipboardManager()
	sender := &clipboardTestSender{}
	payload, _ := json.Marshal(protocol.ClipboardSetData{RequestID: "write", Format: "text/plain", Text: exact})
	manager.HandleClipboardSet(sender, protocol.Message{Data: payload})
	var ack protocol.ClipboardSetAckData
	if err := json.Unmarshal(sender.message.Data, &ack); err != nil {
		t.Fatal(err)
	}
	if !ack.OK {
		t.Fatalf("text alias rejected: %+v", ack)
	}
	manager.HandleClipboardGet(sender, protocol.Message{Data: []byte(`{"request_id":"read","format":"text/plain"}`)})
	var data protocol.ClipboardDataPayload
	if err := json.Unmarshal(sender.message.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Text != exact || data.Format != "text" {
		t.Fatalf("clipboard round trip changed text: %+v", data)
	}
}
