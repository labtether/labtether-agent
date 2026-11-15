package agentcore

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"
)

// Fault: the backoff reset on every successful connect, so a Hub that accepts
// each socket and closes it at once got a reconnect loop with no wait at all.
// A session shorter than minStableSession must count as a failed attempt; a
// stable session, or one that ends with an approved enrollment token,
// reconnects at once and starts the backoff over.
func TestReconnectLoopBacksOffAfterShortSessions(t *testing.T) {
	clock := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	var waits []time.Duration
	transport := &wsTransport{
		runtimeIdentity: newRuntimeIdentitySource(RuntimeConfig{APIToken: "agent-token"}),
		now:             func() time.Time { return clock },
		jitter:          func(time.Duration) time.Duration { return 0 },
		timeAfter: func(d time.Duration) <-chan time.Time {
			waits = append(waits, d)
			ready := make(chan time.Time, 1)
			ready <- clock
			return ready
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connects := 0
	transport.connectWithResponseFn = func(context.Context) (*http.Response, error) {
		connects++
		if connects == 5 {
			// Enrollment approved at once: the Hub's new token arrives and
			// the socket is already closed.
			_ = transport.identitySource().UpdateToken("approved-token")
			return nil, nil
		}
		transport.mu.Lock()
		transport.connected = true
		transport.mu.Unlock()
		return nil, nil
	}
	onConnect := func() {
		switch connects {
		case 3:
			clock = clock.Add(minStableSession) // a stable session
		case 6:
			cancel() // shutting down: no wait may follow
		}
		transport.markDisconnected() // the Hub closes the socket
	}

	done := make(chan struct{})
	go func() {
		transport.reconnectLoop(ctx, onConnect)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("reconnect loop did not stop")
	}

	if connects != 6 {
		t.Fatalf("connects=%d, want 6", connects)
	}
	// Sessions 1 and 2 are short: 1 s, then 2 s. Session 3 is stable: no
	// wait, backoff reset. Session 4 is short again: 1 s. Session 5 ends
	// with a new token and session 6 with shutdown: no wait.
	want := []time.Duration{time.Second, 2 * time.Second, time.Second}
	if !reflect.DeepEqual(waits, want) {
		t.Fatalf("waits=%v, want %v", waits, want)
	}
}
