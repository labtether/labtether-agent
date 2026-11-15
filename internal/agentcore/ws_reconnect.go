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
// A session shorter than minStableSession counts as a failed attempt.
func (t *wsTransport) reconnectLoop(ctx context.Context, onConnect func()) {
	backoff := time.Second

	defer func() {
		// Ensure state reflects "disconnected" (not stuck on "connecting")
		// when the reconnect loop exits.
		t.mu.Lock()
		t.lastError = ""
		t.lastErrorReason = ""
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

		if t.waitingAfterRejection() {
			select {
			case <-ctx.Done():
				return
			case <-t.after(5 * time.Second):
				continue
			}
		}

		tokenBefore := t.identitySource().Snapshot().BearerToken
		resp, err := t.connectAttempt(ctx)
		if err != nil {
			kind := classifyConnectError(err, resp)
			now := t.currentTime()

			t.mu.Lock()
			t.lastError = kind.String()
			t.lastErrorReason = classifyConnectReason(err, resp)
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
							if refusal := enrollmentRefusalMessage(reErr); refusal != "" {
								t.setEnrollmentRefusal(refusal)
							}
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
					if t.tlsCAOnly {
						log.Printf("agentws: the Hub's certificate is not signed by the CA in LABTETHER_TLS_CA_FILE, and %s=true trusts nothing else. If the Hub has a new CA, put it in that file.", envTLSCAOnly)
					} else {
						log.Printf("agentws: TLS certificate trust failed. Configure LABTETHER_TLS_CA_FILE with the hub CA, or temporarily set LABTETHER_TLS_SKIP_VERIFY=true for bootstrap only.")
					}
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

		// Connected: record the reconnect and notify. The backoff resets only
		// after a stable session (see waitAfterSession).
		openedAt := t.currentTime()
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

		if ctx.Err() != nil {
			return
		}
		if wait := t.waitAfterSession(openedAt, tokenBefore, &backoff); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-t.after(wait):
			}
		}
	}
}

// minStableSession is how long a session must last before its end resets the
// reconnect backoff. A Hub that accepts each socket and closes it at once
// used to get a reconnect loop with no wait at all.
const minStableSession = 30 * time.Second

// waitAfterSession returns how long to wait before reconnecting after a
// session ends. A session that lasted minStableSession, or that ended because
// the Hub approved enrollment and gave a new token, reconnects at once and
// resets the backoff. A shorter session counts as a failed attempt: it waits
// the current backoff with jitter, and the backoff grows.
func (t *wsTransport) waitAfterSession(openedAt time.Time, tokenBefore string, backoff *time.Duration) time.Duration {
	lasted := t.currentTime().Sub(openedAt)
	if lasted >= minStableSession || t.identitySource().Snapshot().BearerToken != tokenBefore {
		*backoff = time.Second
		return 0
	}
	wait := *backoff + t.jitterDuration(*backoff/4)
	*backoff = time.Duration(math.Min(float64(*backoff*2), float64(maxBackoff)))
	log.Printf("agentws: the connection to the Hub closed after %s; retrying in %s",
		lasted.Round(time.Millisecond), wait.Round(time.Millisecond))
	return wait
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
