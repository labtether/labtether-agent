package remoteaccess

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/labtether/protocol"
)

type lifecycleSender struct {
	mu       sync.Mutex
	messages []protocol.Message
	err      error
}

func (s *lifecycleSender) Send(msg protocol.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
	return s.err
}

func lifecycleMessage(t *testing.T, data any) protocol.Message {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Message{Data: encoded}
}

func waitLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session lifecycle did not finish")
	}
}

func TestDesktopInputDuringStartupDoesNotPanic(t *testing.T) {
	dm := NewDesktopManager(nil)
	for _, pending := range []*DesktopSession{nil, {sessionID: "pending"}} {
		dm.Sessions["pending"] = pending
		dm.HandleDesktopData(lifecycleMessage(t, protocol.DesktopDataPayload{
			SessionID: "pending", Data: base64.StdEncoding.EncodeToString([]byte("early input")),
		}))
	}
}

func TestDesktopCancelledStartupCannotReplaceNewSession(t *testing.T) {
	originalStart, originalDial := StartDesktopVNCServer, DialDesktopVNC
	t.Cleanup(func() { StartDesktopVNCServer, DialDesktopVNC = originalStart, originalDial })
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	StartDesktopVNCServer = func(string, string, string) (*exec.Cmd, *exec.Cmd, *exec.Cmd, int, string, error) {
		close(entered)
		<-release
		return nil, nil, nil, 5901, "", nil
	}
	conn, peer := net.Pipe()
	defer peer.Close()
	DialDesktopVNC = func(string, string, time.Duration) (net.Conn, error) { return conn, nil }
	dm := NewDesktopManager(nil)
	sender := &lifecycleSender{}
	msg := lifecycleMessage(t, protocol.DesktopStartData{SessionID: "reused"})
	go func() { defer close(finished); dm.HandleDesktopStart(sender, msg) }()
	waitLifecycle(t, entered)
	dm.HandleDesktopClose(lifecycleMessage(t, protocol.DesktopCloseData{SessionID: "reused"}))
	replacement := &DesktopSession{sessionID: "reused"}
	dm.Mu.Lock()
	dm.Sessions["reused"] = replacement
	dm.Mu.Unlock()
	close(release)
	waitLifecycle(t, finished)
	if dm.Sessions["reused"] != replacement {
		t.Fatal("cancelled startup replaced the new desktop")
	}
	if len(sender.messages) != 0 {
		t.Fatal("cancelled startup sent stale state to the new desktop")
	}
	if _, err := conn.Write([]byte("closed")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("old connection remains open: %v", err)
	}
}

func TestDesktopOldStreamCannotCloseReplacement(t *testing.T) {
	oldConn, oldPeer := net.Pipe()
	newConn, newPeer := net.Pipe()
	defer oldPeer.Close()
	defer newPeer.Close()
	defer newConn.Close()
	old := &DesktopSession{sessionID: "reused", vncConn: oldConn, done: make(chan struct{})}
	replacement := &DesktopSession{sessionID: "reused", vncConn: newConn, done: make(chan struct{})}
	dm := NewDesktopManager(nil)
	dm.Sessions["reused"] = replacement
	if dm.cleanupSession(old) {
		t.Fatal("old session still owned replacement")
	}
	if dm.Sessions["reused"] != replacement {
		t.Fatal("old session removed replacement")
	}
	select {
	case <-replacement.done:
		t.Fatal("replacement closed")
	default:
	}
}

func TestTerminalCancelledStartupCannotReplaceNewSession(t *testing.T) {
	original := StartTerminalPTY
	t.Cleanup(func() { StartTerminalPTY = original })
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	StartTerminalPTY = func(*exec.Cmd, *pty.Winsize) (*os.File, error) {
		close(entered)
		<-release
		return reader, nil
	}
	tm := NewTerminalManager()
	sender := &lifecycleSender{}
	msg := lifecycleMessage(t, protocol.TerminalStartData{SessionID: "reused"})
	go func() { defer close(finished); tm.HandleTerminalStart(sender, msg) }()
	waitLifecycle(t, entered)
	tm.HandleTerminalClose(lifecycleMessage(t, protocol.TerminalCloseData{SessionID: "reused"}))
	replacement := &TerminalSession{sessionID: "reused"}
	tm.Mu.Lock()
	tm.Sessions["reused"] = replacement
	tm.Mu.Unlock()
	close(release)
	waitLifecycle(t, finished)
	if tm.Sessions["reused"] != replacement {
		t.Fatal("cancelled startup replaced the new terminal")
	}
	if len(sender.messages) != 0 {
		t.Fatal("cancelled startup sent stale state to the new terminal")
	}
	if _, err := reader.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("cancelled terminal is still open: %v", err)
	}
}

func TestTerminalOldStreamCannotCloseReplacement(t *testing.T) {
	tm := NewTerminalManager()
	old := &TerminalSession{sessionID: "reused"}
	replacement := &TerminalSession{sessionID: "reused"}
	tm.Sessions["reused"] = replacement
	if tm.cleanupSession(old) {
		t.Fatal("old terminal still owned replacement")
	}
	if tm.Sessions["reused"] != replacement {
		t.Fatal("old terminal removed replacement")
	}
}

func TestDesktopSendFailureEndsStream(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	dm := NewDesktopManager(nil)
	sess := &DesktopSession{sessionID: "failed", vncConn: conn, done: make(chan struct{})}
	dm.Sessions[sess.sessionID] = sess
	finished := make(chan struct{})
	go func() { defer close(finished); dm.streamVNCOutput(&lifecycleSender{err: io.ErrClosedPipe}, sess) }()
	if _, err := peer.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	waitLifecycle(t, finished)
	if len(dm.Sessions) != 0 {
		t.Fatal("failed transport kept desktop active")
	}
}

func TestTerminalBlockedInputReleasesWorker(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	sess := &TerminalSession{input: writer}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if _, err := sess.writeWithTimeout([]byte("blocked"), 10*time.Millisecond); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("stalled terminal write = %v, want closed pipe", err)
		}
	}()
	waitLifecycle(t, finished)
}
