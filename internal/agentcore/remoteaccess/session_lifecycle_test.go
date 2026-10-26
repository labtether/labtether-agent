package remoteaccess

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

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

func waitLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session lifecycle did not finish")
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
