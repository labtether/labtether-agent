package remoteaccess

import (
	"encoding/json"
	"github.com/labtether/protocol"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestDesktopPreparedCloseCancelsLateDialAndPreservesReplacement(t *testing.T) {
	oldStart, oldDial := StartDesktopVNCServer, DialDesktopVNC
	defer func() { StartDesktopVNCServer = oldStart; DialDesktopVNC = oldDial }()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	StartDesktopVNCServer = func(string, string, string) (*exec.Cmd, *exec.Cmd, *exec.Cmd, int, string, error) {
		return nil, nil, nil, 5900, "", nil
	}
	DialDesktopVNC = func(string, string, time.Duration) (net.Conn, error) { close(entered); <-release; return conn, nil }
	dm := NewDesktopManager(nil)
	defer dm.CloseAll()
	sender := &terminalStartMessages{}
	raw, _ := json.Marshal(protocol.DesktopStartData{SessionID: "same"})
	msg := protocol.Message{Data: raw}
	start := dm.PrepareDesktopStart(sender, msg)
	if start == nil {
		t.Fatal("missing initial reservation")
	}
	if dm.PrepareDesktopStart(sender, msg) != nil {
		t.Fatal("duplicate pending start accepted")
	}
	done := make(chan struct{})
	go func() { defer close(done); start() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not begin")
	}
	stopRaw, _ := json.Marshal(protocol.DesktopCloseData{SessionID: "same"})
	dm.PrepareDesktopClose(protocol.Message{Data: stopRaw})
	if dm.PrepareDesktopStart(sender, msg) == nil {
		t.Fatal("replacement reservation rejected")
	}
	dm.Mu.Lock()
	replacement := dm.pending["same"]
	dm.Mu.Unlock()
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old start did not finish")
	}
	dm.Mu.Lock()
	kept := dm.pending["same"] == replacement && dm.Sessions["same"] == nil
	dm.Mu.Unlock()
	if !kept {
		t.Fatal("late startup replaced new reservation")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late VNC connection leaked")
	}
	if len(sender.snapshot()) != 0 {
		t.Fatal("canceled start sent desktop state")
	}
}
