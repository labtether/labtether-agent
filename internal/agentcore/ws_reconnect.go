package agentcore

import (
	"context"
	cryptorand "crypto/rand"
	"log"
	"math"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// classifyConnectError inspects the error and HTTP response from a WebSocket
// dial attempt and returns the error kind.
func classifyConnectError(err error, resp *http.Response) connectErrorKind {
	if err == nil {
		return errKindNone
	}
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return errKindAuth
		}
	}
	return errKindTransient
}

func jitterDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// reconnectLoop attempts to maintain a persistent WebSocket connection with
// exponential backoff (1s, 2s, 4s, 8s... cap 60s) and jitter. Auth failures
// (401/403) back off to 5-minute intervals after 3 consecutive failures.
func (t *wsTransport) reconnectLoop(ctx context.Context, onConnect func()) {
	backoff := time.Second

	defer func() {
		// Ensure state reflects "disconnected" (not stuck on "connecting")
		// when the reconnect loop exits.
		t.mu.Lock()
		t.lastError = ""
		t.mu.Unlock()
		t.markDisconnected()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if t.socketOpen() {
			// Wait a bit before checking again.
			select {
			case <-ctx.Done():
				return
			case <-t.after(time.Second):
				continue
			}
		}

		resp, err := t.connectAttempt(ctx)
		if err != nil {
			kind := classifyConnectError(err, resp)
			now := t.currentTime()

			t.mu.Lock()
			t.lastError = kind.String()
			t.lastErrorAt = now
			if t.disconnectedAt.IsZero() {
				t.disconnectedAt = now
			}

			var wait time.Duration
			if kind == errKindAuth {
				t.consecutiveAuthFailures++
				failures := t.consecutiveAuthFailures
				reEnroll := t.reEnrollFn
				lastReEnroll := t.lastReEnrollAt
				if failures >= authFailureThreshold {
					wait = authBackoff
					t.mu.Unlock()
					log.Printf("agentws: AUTH FAILURE (%d consecutive) — credentials rejected by hub, backing off to %s: %v",
						failures, wait, err)

					// Attempt re-enrollment if available and not too recent.
					if reEnroll != nil && t.currentTime().Sub(lastReEnroll) > 10*time.Minute {
						log.Printf("agentws: attempting re-enrollment after %d auth failures", failures)
						if newToken, reErr := reEnroll(); reErr == nil {
							t.updateToken(newToken)
							t.mu.Lock()
							t.lastReEnrollAt = t.currentTime().UTC()
							t.mu.Unlock()
							log.Printf("agentws: re-enrollment succeeded, retrying connection")
							backoff = time.Second
							continue
						} else {
							log.Printf("agentws: re-enrollment failed: %v", reErr)
							t.mu.Lock()
							t.lastReEnrollAt = t.currentTime().UTC()
							t.mu.Unlock()
						}
					}
				} else {
					t.mu.Unlock()
					jitter := t.jitterDuration(backoff / 4)
					wait = backoff + jitter
					log.Printf("agentws: auth failure (%d/%d), retrying in %s: %v",
						failures, authFailureThreshold, wait, err)
					backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
				}
			} else {
				t.mu.Unlock()
				jitter := t.jitterDuration(backoff / 4)
				wait = backoff + jitter
				log.Printf("agentws: connect failed, retrying in %s: %v", wait, err)
				if backoff == time.Second && isTLSTrustError(err) {
					log.Printf("agentws: TLS certificate trust failed. Configure LABTETHER_TLS_CA_FILE with the hub CA, or temporarily set LABTETHER_TLS_SKIP_VERIFY=true for bootstrap only.")
				}
				backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
			}

			select {
			case <-ctx.Done():
				return
			case <-t.after(wait):
			}
			continue
		}

		// Connected — reset backoff, record the reconnect, and notify.
		backoff = time.Second
		atomic.AddInt64(&t.reconnectCount, 1)
		if onConnect != nil && t.Connected() {
			onConnect()
		}

		// Block on receive loop (handled elsewhere); just wait for disconnect.
		// The receive loop in the runtime will call markDisconnected on error.
		// Also listen for network changes to force an immediate reconnect.
		netCh := t.networkChanged
		if netCh == nil {
			netCh = make(chan struct{}) // never fires
		}
		for t.socketOpen() {
			select {
			case <-ctx.Done():
				return
			case <-netCh:
				log.Printf("agentws: network change — forcing reconnect")
				t.markDisconnected()
			case <-t.after(time.Second):
			}
		}
	}
}

func isTLSTrustError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "x509:") {
		return false
	}
	return strings.Contains(lower, "unknown authority") ||
		strings.Contains(lower, "failed to verify certificate") ||
		strings.Contains(lower, "certificate is not trusted")
}
