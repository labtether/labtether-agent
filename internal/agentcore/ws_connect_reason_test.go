package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Risk: a lab Mac blocked by the Local Network permission showed only
// "transient" while connecting forever. The reason must be classified from the
// real dial error chains that gorilla/websocket returns on each platform.
func TestClassifyConnectReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		resp *http.Response
		want string
	}{
		{"real refused dial", realDialError(t, "ws://"+closedLoopbackAddr(t)+"/ws/agent"), nil, connectReasonRefused},
		{"real untrusted hub certificate", realDialError(t, "wss://"+tlsHubAddr(t)+"/ws/agent"), nil, connectReasonCertificate},
		{"connect not permitted", &net.OpError{Op: "dial", Net: "tcp",
			Err: os.NewSyscallError("connect", syscall.EPERM)}, nil, connectReasonUnreachable},
		{"host unreachable", &net.OpError{Op: "dial", Net: "tcp",
			Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, nil, connectReasonUnreachable},
		// The lab Mac's blocked dial matched none of the listed errno values.
		{"other dial failure", &net.OpError{Op: "dial", Net: "tcp",
			Err: os.NewSyscallError("connect", syscall.ENETDOWN)}, nil, connectReasonUnreachable},
		{"read failure after connect", &net.OpError{Op: "read", Net: "tcp",
			Err: os.NewSyscallError("read", syscall.ECONNRESET)}, nil, ""},
		{"Windows unreachable host text", errors.New(
			"dial tcp 192.0.2.10:8443: connectex: A socket operation was attempted to an unreachable host."),
			nil, connectReasonUnreachable},
		{"Windows refused text", errors.New("dial tcp 192.0.2.10:8443: connectex: No connection could be made " +
			"because the target machine actively refused it."), nil, connectReasonRefused},
		{"name lookup", &net.OpError{Op: "dial", Net: "tcp",
			Err: &net.DNSError{Err: "no such host", Name: "hub.example.com", IsNotFound: true}}, nil, connectReasonNameLookup},
		{"handshake deadline", context.DeadlineExceeded, nil, connectReasonTimedOut},
		{"token rejected", errors.New("websocket: bad handshake"),
			&http.Response{StatusCode: http.StatusUnauthorized}, connectReasonTokenRejected},
		{"unknown hub reply", errors.New("websocket: bad handshake"),
			&http.Response{StatusCode: http.StatusBadGateway}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyConnectReason(tc.err, tc.resp); got != tc.want {
				t.Fatalf("classifyConnectReason(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// Risk: the reason must reach /agent/status without changing last_error,
// which the Mac and Windows apps already switch on.
func TestStatusReportsConnectReasonAndKeepsKind(t *testing.T) {
	transport := newWSTransport("wss://hub.example.com/ws/agent", "tok", "node-42", "darwin", "v1.2.3", nil, "", nil)
	transport.jitter = func(time.Duration) time.Duration { return 0 }
	transport.connectWithResponseFn = func(context.Context) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
	}
	rt := NewRuntime(RuntimeConfig{Name: "test-agent", Port: "9100", CollectInterval: time.Minute,
		HeartbeatInterval: time.Minute}, stubProvider{}, noopHeartbeatPublisher{})
	rt.transport = transport

	ctx, cancel := context.WithCancel(context.Background())
	var resp StatusResponse
	transport.timeAfter = func(time.Duration) <-chan time.Time {
		rec := httptest.NewRecorder()
		rt.statusHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agent/status", nil))
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Errorf("decode status: %v", err)
		}
		cancel()
		return make(chan time.Time)
	}
	transport.reconnectLoop(ctx, nil)

	if resp.ConnectionState != "connecting" || resp.LastError != "transient" ||
		resp.LastErrorReason != connectReasonUnreachable {
		t.Fatalf("status = (%q, %q, %q), want (connecting, transient, %s)",
			resp.ConnectionState, resp.LastError, resp.LastErrorReason, connectReasonUnreachable)
	}
	if got := transport.ConnectionErrorReason(); got != "" {
		t.Fatalf("reason after loop exit = %q, want empty", got)
	}
}

func realDialError(t *testing.T, rawURL string) error {
	t.Helper()
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(rawURL, nil)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("dial %s succeeded, want an error", rawURL)
	}
	return err
}

func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func tlsHubAddr(t *testing.T) string {
	t.Helper()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "https://")
}
