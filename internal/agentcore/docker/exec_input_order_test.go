package docker

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
)

func TestOldExecSessionCleanupCannotCloseReplacement(t *testing.T) {
	manager := NewDockerExecManager(nil)
	oldConn, oldPeer := net.Pipe()
	defer oldPeer.Close()
	old := &dockerExecSession{sessionID: "same-id", conn: oldConn, inputWriter: streaminput.New(oldConn, nil)}
	replacement := &dockerExecSession{sessionID: "same-id"}
	manager.sessions["same-id"] = replacement
	if manager.cleanupSession(old) || manager.sessions["same-id"] != replacement {
		t.Fatal("old exec exit removed its replacement")
	}
	_ = oldPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := oldPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("old exec input leaked: %v", err)
	}
}
