package remoteaccess

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
	"github.com/labtether/protocol"
)

func TestDesktopInputStallDoesNotBlockOtherSessionOrClose(t *testing.T) {
	manager := NewDesktopManager(nil)
	defer manager.CloseAll()
	stalled, stalledPeer := net.Pipe()
	defer stalledPeer.Close()
	active, activePeer := net.Pipe()
	defer activePeer.Close()
	makeSession := func(id string, conn net.Conn) *DesktopSession {
		return &DesktopSession{sessionID: id, vncConn: conn, inputWriter: streaminput.New(conn, nil), done: make(chan struct{})}
	}
	manager.Sessions["stalled"] = makeSession("stalled", stalled)
	manager.Sessions["active"] = makeSession("active", active)
	input := func(id, text string) {
		raw, _ := json.Marshal(protocol.DesktopDataPayload{SessionID: id, Data: base64.StdEncoding.EncodeToString([]byte(text))})
		manager.HandleDesktopData(protocol.Message{Type: protocol.MsgDesktopData, Data: raw})
	}
	returned := make(chan struct{})
	go func() {
		input("stalled", "unread")
		input("active", "a")
		input("active", "b")
		raw, _ := json.Marshal(protocol.DesktopCloseData{SessionID: "stalled"})
		manager.HandleDesktopClose(protocol.Message{Type: protocol.MsgDesktopClose, Data: raw})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("stalled VNC write kept the close request from being handled")
	}
	_ = activePeer.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 2)
	if _, err := io.ReadFull(activePeer, got); err != nil || string(got) != "ab" {
		t.Fatalf("other session input=%q error=%v", got, err)
	}
	_ = stalledPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalledPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("stalled session not closed: %v", err)
	}
}

func TestOldSessionCleanupCannotCloseReplacement(t *testing.T) {
	t.Run("desktop", func(t *testing.T) {
		manager := NewDesktopManager(nil)
		oldConn, oldPeer := net.Pipe()
		defer oldPeer.Close()
		old := &DesktopSession{sessionID: "same-id", vncConn: oldConn, inputWriter: streaminput.New(oldConn, nil), done: make(chan struct{})}
		replacement := &DesktopSession{sessionID: "same-id"}
		manager.Sessions["same-id"] = replacement
		if manager.cleanupSession(old) || manager.Sessions["same-id"] != replacement {
			t.Fatal("old VNC stream removed its replacement")
		}
		_ = oldPeer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := oldPeer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("old VNC stream leaked: %v", err)
		}
	})
	t.Run("terminal", func(t *testing.T) {
		manager := NewTerminalManager()
		oldConn, oldPeer := net.Pipe()
		defer oldPeer.Close()
		old := &TerminalSession{sessionID: "same-id", inputWriter: streaminput.New(oldConn, nil)}
		replacement := &TerminalSession{sessionID: "same-id"}
		manager.Sessions["same-id"] = replacement
		if manager.cleanupSession(old) || manager.Sessions["same-id"] != replacement {
			t.Fatal("old shell exit removed its replacement")
		}
		_ = oldPeer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := oldPeer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("old terminal input leaked: %v", err)
		}
	})
}
