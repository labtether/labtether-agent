package agentcore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
)

func TestInboundMessageAllowedDuringEnrollment(t *testing.T) {
	tests := []struct {
		name        string
		messageType string
		want        bool
	}{
		{name: "challenge", messageType: protocol.MsgEnrollmentChallenge, want: true},
		{name: "approved", messageType: protocol.MsgEnrollmentApproved, want: true},
		{name: "rejected", messageType: protocol.MsgEnrollmentRejected, want: true},
		{name: "command", messageType: protocol.MsgCommandRequest, want: false},
		{name: "ping", messageType: protocol.MsgPing, want: false},
		{name: "unknown", messageType: "future.operational.message", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inboundMessageAllowed(true, tt.messageType); got != tt.want {
				t.Fatalf("inboundMessageAllowed(true, %q) = %v, want %v", tt.messageType, got, tt.want)
			}
			if got := inboundMessageAllowed(false, tt.messageType); !got {
				t.Fatalf("inboundMessageAllowed(false, %q) = false, want true", tt.messageType)
			}
		})
	}
}

func TestReceiveLoopDoesNotDispatchCommandsUntilAuthenticated(t *testing.T) {
	originalHandleCommandRequest := handleCommandRequest
	t.Cleanup(func() { handleCommandRequest = originalHandleCommandRequest })

	commandCalls := make(chan struct{}, 2)
	handleCommandRequest = func(_ *wsTransport, _ protocol.Message, _ RuntimeConfig) {
		commandCalls <- struct{}{}
	}

	t.Run("pending enrollment ignores command", func(t *testing.T) {
		transport, serverConn, stop := startReceiveLoopForEnrollmentTest(t, true)
		defer stop()

		if err := serverConn.WriteJSON(protocol.Message{Type: protocol.MsgCommandRequest}); err != nil {
			t.Fatalf("send command request: %v", err)
		}
		waitForReceiveCount(t, transport, 1)

		select {
		case <-commandCalls:
			t.Fatal("command handler ran on a pending enrollment socket")
		case <-time.After(150 * time.Millisecond):
		}
	})

	t.Run("authenticated socket dispatches command", func(t *testing.T) {
		_, serverConn, stop := startReceiveLoopForEnrollmentTest(t, false)
		defer stop()

		if err := serverConn.WriteJSON(protocol.Message{Type: protocol.MsgCommandRequest}); err != nil {
			t.Fatalf("send command request: %v", err)
		}

		select {
		case <-commandCalls:
		case <-time.After(2 * time.Second):
			t.Fatal("authenticated command handler was not dispatched")
		}
	})
}

func startReceiveLoopForEnrollmentTest(t *testing.T, enrollmentPending bool) (*wsTransport, *websocket.Conn, func()) {
	t.Helper()

	serverConnCh := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		serverConnCh <- conn
	}))

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial websocket: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		server.Close()
		t.Fatal("timed out waiting for websocket connection")
	}

	token := "authenticated-test-token"
	if enrollmentPending {
		token = ""
	}
	transport := &wsTransport{
		runtimeIdentity:   newRuntimeIdentitySource(RuntimeConfig{APIToken: token}),
		conn:              clientConn,
		connected:         true,
		pendingEnrollment: enrollmentPending,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fileBaseDir := t.TempDir()
	go func() {
		defer close(done)
		receiveLoop(
			ctx,
			transport,
			RuntimeConfig{},
			nil,
			newTerminalManager(),
			newDesktopManager(nil),
			nil,
			&files.Manager{BaseDir: fileBaseDir},
			nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil,
			nil, nil, nil, nil,
		)
	}()

	stop := func() {
		cancel()
		transport.Close()
		_ = serverConn.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("receive loop did not stop")
		}
		server.Close()
	}
	return transport, serverConn, stop
}

func waitForReceiveCount(t *testing.T, transport *wsTransport, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&transport.messagesReceived) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("messages received = %d, want at least %d", atomic.LoadInt64(&transport.messagesReceived), want)
}
