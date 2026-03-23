package agentcore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/remoteaccess"
	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"

	"github.com/labtether/protocol"
)

func TestClipboardManagerHandleClipboardGetDefaultsToText(t *testing.T) {
	originalRead := sysconfig.ClipboardRead
	t.Cleanup(func() {
		sysconfig.ClipboardRead = originalRead
	})

	sysconfig.ClipboardRead = func(format string) (string, string, error) {
		if format != "text" {
			t.Fatalf("format=%q, want text", format)
		}
		return "hello from clipboard", "", nil
	}

	transport, messages, cleanup := newDesktopRuntimeTransport(t)
	defer cleanup()

	manager := newClipboardManager()
	manager.HandleClipboardGet(transport, protocol.Message{
		Type: protocol.MsgClipboardGet,
		Data: mustMarshalDesktopRuntime(t, protocol.ClipboardGetData{RequestID: "req-get"}),
	})

	msg := readDesktopRuntimeMessage(t, messages)
	if msg.Type != protocol.MsgClipboardData {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgClipboardData)
	}
	var payload protocol.ClipboardDataPayload
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode clipboard data payload: %v", err)
	}
	if payload.RequestID != "req-get" {
		t.Fatalf("request_id=%q, want req-get", payload.RequestID)
	}
	if payload.Format != "text" || payload.Text != "hello from clipboard" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestClipboardManagerHandleClipboardSetUsesFormatSpecificWriters(t *testing.T) {
	originalText := sysconfig.ClipboardWriteText
	originalImage := sysconfig.ClipboardWriteImage
	t.Cleanup(func() {
		sysconfig.ClipboardWriteText = originalText
		sysconfig.ClipboardWriteImage = originalImage
	})

	t.Run("image path", func(t *testing.T) {
		var gotImage string
		sysconfig.ClipboardWriteText = func(string) error {
			t.Fatal("did not expect text writer for image clipboard set")
			return nil
		}
		sysconfig.ClipboardWriteImage = func(data string) error {
			gotImage = data
			return nil
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := newClipboardManager()
		manager.HandleClipboardSet(transport, protocol.Message{
			Type: protocol.MsgClipboardSet,
			Data: mustMarshalDesktopRuntime(t, protocol.ClipboardSetData{
				RequestID: "req-image",
				Format:    "image/png",
				Data:      "png-base64",
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgClipboardSetAck {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgClipboardSetAck)
		}
		var ack protocol.ClipboardSetAckData
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			t.Fatalf("decode clipboard ack payload: %v", err)
		}
		if !ack.OK || ack.RequestID != "req-image" {
			t.Fatalf("unexpected ack: %+v", ack)
		}
		if gotImage != "png-base64" {
			t.Fatalf("image data=%q, want png-base64", gotImage)
		}
	})

	t.Run("text error path", func(t *testing.T) {
		sysconfig.ClipboardWriteImage = func(string) error { return nil }
		sysconfig.ClipboardWriteText = func(text string) error {
			if text != "hello" {
				t.Fatalf("text=%q, want hello", text)
			}
			return errors.New("xclip failed")
		}

		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		manager := newClipboardManager()
		manager.HandleClipboardSet(transport, protocol.Message{
			Type: protocol.MsgClipboardSet,
			Data: mustMarshalDesktopRuntime(t, protocol.ClipboardSetData{
				RequestID: "req-text",
				Format:    "text",
				Text:      "hello",
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		var ack protocol.ClipboardSetAckData
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			t.Fatalf("decode clipboard ack payload: %v", err)
		}
		if ack.OK {
			t.Fatalf("expected failed ack, got %+v", ack)
		}
		if !strings.Contains(ack.Error, "xclip failed") {
			t.Fatalf("ack error=%q, want xclip failed", ack.Error)
		}
	})
}

func TestAudioSidebandManagerHandleAudioStartStreamsDataAndStopsOnEOF(t *testing.T) {
	originalStart := remoteaccess.StartAudioCapture
	t.Cleanup(func() {
		remoteaccess.StartAudioCapture = originalStart
	})

	reader, writer := io.Pipe()
	remoteaccess.StartAudioCapture = func(_ context.Context, sessionID string, bitrate int) (io.Reader, error) {
		if sessionID != "sess-audio" {
			t.Fatalf("sessionID=%q, want sess-audio", sessionID)
		}
		if bitrate != 64000 {
			t.Fatalf("bitrate=%d, want 64000", bitrate)
		}
		return reader, nil
	}

	transport, messages, cleanup := newDesktopRuntimeTransport(t)
	defer cleanup()

	manager := newAudioSidebandManager()
	manager.HandleAudioStart(transport, protocol.Message{
		Type: protocol.MsgDesktopAudioStart,
		Data: mustMarshalDesktopRuntime(t, protocol.DesktopAudioStartData{
			SessionID: "sess-audio",
			Bitrate:   64000,
		}),
	})

	started := readDesktopAudioState(t, messages)
	if started.State != "started" {
		t.Fatalf("state=%q, want started", started.State)
	}

	if _, err := writer.Write([]byte("opus-payload")); err != nil {
		t.Fatalf("write audio chunk: %v", err)
	}
	_ = writer.Close()

	dataMsg := readDesktopRuntimeMessage(t, messages)
	if dataMsg.Type != protocol.MsgDesktopAudioData {
		t.Fatalf("message type=%q, want %q", dataMsg.Type, protocol.MsgDesktopAudioData)
	}
	var data protocol.DesktopAudioDataPayload
	if err := json.Unmarshal(dataMsg.Data, &data); err != nil {
		t.Fatalf("decode audio data payload: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		t.Fatalf("decode audio data: %v", err)
	}
	if string(decoded) != "opus-payload" {
		t.Fatalf("decoded audio=%q, want opus-payload", string(decoded))
	}

	stopped := readDesktopAudioState(t, messages)
	if stopped.State != "stopped" {
		t.Fatalf("state=%q, want stopped", stopped.State)
	}
	waitForAudioSessionRemoval(t, manager, "sess-audio")
}

func TestAudioSidebandManagerHandleAudioStartReportsUnavailable(t *testing.T) {
	originalStart := remoteaccess.StartAudioCapture
	t.Cleanup(func() {
		remoteaccess.StartAudioCapture = originalStart
	})

	remoteaccess.StartAudioCapture = func(context.Context, string, int) (io.Reader, error) {
		return nil, errors.New("ffmpeg missing")
	}

	transport, messages, cleanup := newDesktopRuntimeTransport(t)
	defer cleanup()

	manager := newAudioSidebandManager()
	manager.HandleAudioStart(transport, protocol.Message{
		Type: protocol.MsgDesktopAudioStart,
		Data: mustMarshalDesktopRuntime(t, protocol.DesktopAudioStartData{SessionID: "sess-unavailable"}),
	})

	state := readDesktopAudioState(t, messages)
	if state.State != "unavailable" {
		t.Fatalf("state=%q, want unavailable", state.State)
	}
	if !strings.Contains(state.Error, "ffmpeg missing") {
		t.Fatalf("error=%q, want ffmpeg missing", state.Error)
	}
	waitForAudioSessionRemoval(t, manager, "sess-unavailable")
}

func TestAudioSidebandManagerHandleAudioStopCancelsSession(t *testing.T) {
	originalStart := remoteaccess.StartAudioCapture
	t.Cleanup(func() {
		remoteaccess.StartAudioCapture = originalStart
	})

	reader, writer := io.Pipe()
	remoteaccess.StartAudioCapture = func(context.Context, string, int) (io.Reader, error) {
		return reader, nil
	}

	transport, messages, cleanup := newDesktopRuntimeTransport(t)
	defer cleanup()
	defer writer.Close()

	manager := newAudioSidebandManager()
	manager.HandleAudioStart(transport, protocol.Message{
		Type: protocol.MsgDesktopAudioStart,
		Data: mustMarshalDesktopRuntime(t, protocol.DesktopAudioStartData{SessionID: "sess-stop"}),
	})

	started := readDesktopAudioState(t, messages)
	if started.State != "started" {
		t.Fatalf("state=%q, want started", started.State)
	}

	manager.HandleAudioStop(protocol.Message{
		Type: protocol.MsgDesktopAudioStop,
		Data: mustMarshalDesktopRuntime(t, protocol.DesktopAudioStopData{SessionID: "sess-stop"}),
	})

	_ = writer.Close()

	stopped := readDesktopAudioState(t, messages)
	if stopped.State != "stopped" {
		t.Fatalf("state=%q, want stopped", stopped.State)
	}
	waitForAudioSessionRemoval(t, manager, "sess-stop")
}

func readDesktopAudioState(t *testing.T, messages <-chan protocol.Message) protocol.DesktopAudioStateData {
	t.Helper()
	msg := readDesktopRuntimeMessage(t, messages)
	if msg.Type != protocol.MsgDesktopAudioState {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgDesktopAudioState)
	}
	var state protocol.DesktopAudioStateData
	if err := json.Unmarshal(msg.Data, &state); err != nil {
		t.Fatalf("decode audio state payload: %v", err)
	}
	return state
}

func waitForAudioSessionRemoval(t *testing.T, manager *audioSidebandManager, sessionID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		manager.Mu.Lock()
		_, ok := manager.Sessions[sessionID]
		manager.Mu.Unlock()
		if !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected audio session %s to be removed", sessionID)
}
