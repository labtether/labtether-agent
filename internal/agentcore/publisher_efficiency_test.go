package agentcore

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Fallback heartbeats must reuse one trusted TLS connection when the hub
// returns its normal small JSON acknowledgement, avoiding a handshake per tick.
func TestHeartbeatFallbackReusesConnectionWithJSONReply(t *testing.T) {
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	var connections, requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	publisher := NewHeartbeatPublisher(RuntimeConfig{
		APIBaseURL: server.URL, APIToken: "fixture-token", AssetID: "fixture", TLSCAFile: ca,
	}, nil)
	for range 2 {
		if err := publisher.Publish(context.Background(), TelemetrySample{AssetID: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests=%d, want 2", got)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("TLS connections=%d, want 1 reused connection", got)
	}
}

// A hub error or unexpectedly large reply must not make a heartbeat read an
// unbounded body. The status, rather than unused acknowledgement data, owns
// whether the heartbeat was accepted.
func TestHeartbeatFallbackBoundsReplyAndPreservesStatus(t *testing.T) {
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	for _, statusCode := range []int{http.StatusAccepted, http.StatusServiceUnavailable} {
		body := &heartbeatReplyBody{}
		publisher := NewHeartbeatPublisher(RuntimeConfig{
			APIBaseURL: "https://127.0.0.1", APIToken: "fixture-token", AssetID: "fixture",
		}, nil).(*apiHeartbeatPublisher)
		publisher.client.Transport = heartbeatReplyTransport{statusCode: statusCode, body: body}
		err := publisher.Publish(context.Background(), TelemetrySample{AssetID: "fixture"})
		if statusCode == http.StatusAccepted && err != nil {
			t.Fatal(err)
		}
		if statusCode == http.StatusServiceUnavailable && (err == nil || !strings.Contains(err.Error(), "status 503")) {
			t.Fatalf("rejected reply returned %v", err)
		}
		if body.bytesRead == 0 || body.bytesRead > 64*1024 || !body.closed {
			t.Fatalf("status %d: bytes read=%d, closed=%v", statusCode, body.bytesRead, body.closed)
		}
	}
}

type heartbeatReplyBody struct {
	bytesRead int
	closed    bool
}

func (b *heartbeatReplyBody) Read(buffer []byte) (int, error) {
	if b.bytesRead >= 128*1024 {
		return 0, errors.New("fixture reply exceeds read budget")
	}
	b.bytesRead += len(buffer)
	clear(buffer)
	return len(buffer), nil
}

func (b *heartbeatReplyBody) Close() error { b.closed = true; return nil }

type heartbeatReplyTransport struct {
	statusCode int
	body       *heartbeatReplyBody
}

func (rt heartbeatReplyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: rt.statusCode, Body: rt.body}, nil
}
