package agentcore

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/labtether/protocol"
)

// Error classification for WebSocket connect failures.
type connectErrorKind int

const (
	errKindNone      connectErrorKind = iota
	errKindAuth                       // 401/403 — credentials rejected
	errKindTransient                  // network, DNS, server error, etc.
)

func (k connectErrorKind) String() string {
	switch k {
	case errKindNone:
		return "none"
	case errKindAuth:
		return "auth_failed"
	case errKindTransient:
		return "transient"
	default:
		return "unknown"
	}
}

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

// Reconnect backoff constants.
const (
	maxBackoff                  = 60 * time.Second
	authBackoff                 = 5 * time.Minute
	authFailureThreshold        = 3
	agentTokenPersistenceFailed = "agent_token_persistence_failed" // #nosec G101 -- protocol event key, not a credential.
	enrollmentTokenRejected     = "enrollment_token_rejected"
)

// Client-side keepalive constants. The agent client pings every 25s
// (staggered from the hub's 30s interval). If no pong (or any other
// frame) arrives within 60s the read deadline fires and the connection
// is torn down.
//
// Named "client" to avoid collision with the hub-side clientPingInterval
// (30s) in cmd/labtether/agent_ws_handler.go.
const (
	clientPingInterval = 25 * time.Second
	clientReadDeadline = 60 * time.Second
	// Agent control messages are JSON envelopes containing bounded chunks. A
	// 16 MiB ceiling leaves ample room for desktop/file payloads while ensuring
	// a compromised or malfunctioning hub cannot force unbounded allocation in
	// gorilla/websocket's JSON decoder.
	maxAgentControlMessageBytes int64 = 16 * 1024 * 1024
)

type wsTransport struct {
	runtimeIdentity *runtimeIdentitySource
	identityOnce    sync.Once
	platform        string
	agentVersion    string
	tlsConfig       *tls.Config
	tokenFilePath   string
	deviceIdentity  *deviceIdentity

	// Diagnostic counters — accessed with sync/atomic.
	messagesSent     int64
	messagesReceived int64
	reconnectCount   int64

	startedAt time.Time

	mu                         sync.Mutex
	conn                       *websocket.Conn
	connected                  bool          // true while any WebSocket (pending or authenticated) is open
	pendingEnrollment          bool          // true until the open socket has an authenticated bearer
	pingDone                   chan struct{} // closed to stop ping goroutine
	consecutiveAuthFailures    int
	lastError                  string
	lastErrorAt                time.Time
	disconnectedAt             time.Time
	credentialPersistenceError string
	credentialError            string

	networkChanged <-chan struct{} // signaled when local IPs change

	reEnrollFn     func() (string, error) // returns new token or error
	lastReEnrollAt time.Time

	connectWithResponseFn func(context.Context) (*http.Response, error)
	timeAfter             func(time.Duration) <-chan time.Time
	now                   func() time.Time
	jitter                func(time.Duration) time.Duration
}

// updateToken updates the bearer token and resets auth failure state.
func (t *wsTransport) updateToken(token string) {
	identity := t.identitySource()
	_ = identity.UpdateToken(token)
	t.mu.Lock()
	t.consecutiveAuthFailures = 0
	t.lastError = ""
	t.credentialError = ""
	t.mu.Unlock()
}

func (t *wsTransport) setCredentialPersistenceError(message string) {
	t.mu.Lock()
	t.credentialPersistenceError = strings.TrimSpace(message)
	t.mu.Unlock()
}

func (t *wsTransport) setCredentialError(message string) {
	t.mu.Lock()
	t.credentialError = strings.TrimSpace(message)
	t.mu.Unlock()
}

// AssetID returns the asset ID associated with this transport.
func (t *wsTransport) AssetID() string {
	return t.identitySource().AssetID()
}

func newWSTransport(url, token, assetID, platform, agentVersion string, tlsConfig *tls.Config, tokenFilePath string, identity *deviceIdentity) *wsTransport {
	runtimeIdentity := newRuntimeIdentitySource(RuntimeConfig{
		WSBaseURL:  url,
		APIBaseURL: apiBaseURLFromWS(url),
		APIToken:   token,
		AssetID:    assetID,
	})
	return newWSTransportWithRuntimeIdentity(runtimeIdentity, platform, agentVersion, tlsConfig, tokenFilePath, identity)
}

func newWSTransportWithRuntimeIdentity(runtimeIdentity *runtimeIdentitySource, platform, agentVersion string, tlsConfig *tls.Config, tokenFilePath string, identity *deviceIdentity) *wsTransport {
	if runtimeIdentity == nil {
		runtimeIdentity = newRuntimeIdentitySource(RuntimeConfig{})
	}
	return &wsTransport{
		runtimeIdentity: runtimeIdentity,
		platform:        platform,
		agentVersion:    strings.TrimSpace(agentVersion),
		tlsConfig:       tlsConfig,
		tokenFilePath:   tokenFilePath,
		deviceIdentity:  identity,
		startedAt:       time.Now(),
		timeAfter:       time.After,
		now:             time.Now,
		jitter:          jitterDuration,
	}
}

func (t *wsTransport) identitySource() *runtimeIdentitySource {
	t.identityOnce.Do(func() {
		if t.runtimeIdentity == nil {
			t.runtimeIdentity = newRuntimeIdentitySource(RuntimeConfig{})
		}
	})
	return t.runtimeIdentity
}

func (t *wsTransport) connectAttempt(ctx context.Context) (*http.Response, error) {
	if t.connectWithResponseFn != nil {
		return t.connectWithResponseFn(ctx)
	}
	return t.connectWithResponse(ctx)
}

func (t *wsTransport) after(d time.Duration) <-chan time.Time {
	if t.timeAfter != nil {
		return t.timeAfter(d)
	}
	return time.After(d)
}

func (t *wsTransport) currentTime() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *wsTransport) jitterDuration(max time.Duration) time.Duration {
	if t.jitter != nil {
		return t.jitter(max)
	}
	return jitterDuration(max)
}

// connectWithResponse dials the hub and returns the HTTP response alongside the
// error so callers can inspect the status code for error classification.
func (t *wsTransport) connectWithResponse(ctx context.Context) (*http.Response, error) {
	identity := t.identitySource()
	identitySnapshot := identity.Snapshot()
	if err := validateWebSocketTransportURL(identitySnapshot.WSBaseURL); err != nil {
		return nil, err
	}
	token := identitySnapshot.BearerToken
	assetID := identitySnapshot.AssetID

	header := http.Header{}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	} else {
		header.Set("X-Request-Enrollment", "true")
		hostname, _ := os.Hostname()
		header.Set("X-Hostname", hostname)
		if t.deviceIdentity != nil {
			header.Set("X-Device-Fingerprint", t.deviceIdentity.Fingerprint)
			header.Set("X-Device-Key-Alg", t.deviceIdentity.KeyAlgorithm)
			header.Set("X-Device-Public-Key", t.deviceIdentity.PublicKeyBase64)
		}
	}
	header.Set("X-Asset-ID", assetID)
	header.Set("X-Platform", t.platform)
	if t.agentVersion != "" {
		header.Set("X-Agent-Version", t.agentVersion)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  t.tlsConfig,
	}

	conn, resp, err := dialer.DialContext(ctx, identitySnapshot.WSBaseURL, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return resp, err
	}
	conn.SetReadLimit(maxAgentControlMessageBytes)

	// Newer hubs return the token-bound canonical asset ID in the successful
	// upgrade response. Adopt and persist it so agents enrolled by an older
	// build can self-heal a stale pre-enrollment asset ID on their next connect.
	canonicalAssetID := ""
	connectionIdentity := identitySnapshot
	if resp != nil {
		canonicalAssetID = strings.TrimSpace(resp.Header.Get("X-LabTether-Asset-ID"))
	}
	if token != "" && canonicalAssetID != "" {
		if !validPersistedAssetID(canonicalAssetID) {
			_ = conn.Close()
			return resp, fmt.Errorf("hub returned an invalid canonical asset ID")
		}
		adopted, applied, adoptErr := identity.AdoptCanonicalAsset(identitySnapshot, canonicalAssetID)
		if adoptErr != nil {
			_ = conn.Close()
			return resp, adoptErr
		}
		if applied {
			connectionIdentity = adopted
			if err := saveEnrollmentState(t.tokenFilePath, enrollmentState{
				AssetID:   adopted.AssetID,
				HubWSURL:  adopted.WSBaseURL,
				HubAPIURL: adopted.APIBaseURL,
			}); err != nil {
				log.Printf("agentws: warning: failed to persist canonical asset ID: %v", err)
			}
		}
	}
	if !identity.MatchesConnection(connectionIdentity) {
		_ = conn.Close()
		return resp, errRuntimeIdentityChanged
	}

	// Set initial read deadline; the pong handler resets it on each pong.
	_ = conn.SetReadDeadline(time.Now().Add(clientReadDeadline))
	conn.SetPongHandler(func(_ string) error {
		return conn.SetReadDeadline(time.Now().Add(clientReadDeadline))
	})

	t.mu.Lock()
	if t.conn != nil {
		_ = t.conn.Close()
	}
	// Stop the previous ping goroutine if one is running.
	if t.pingDone != nil {
		close(t.pingDone)
	}
	pingDone := make(chan struct{})
	t.pingDone = pingDone
	t.conn = conn
	t.connected = true
	t.pendingEnrollment = token == ""
	t.consecutiveAuthFailures = 0
	t.lastError = ""
	t.disconnectedAt = time.Time{}
	t.mu.Unlock()

	go t.pingLoop(conn, pingDone)

	if token == "" {
		log.Printf("agentws: pending enrollment socket connected to %s", websocketOriginForLog(identitySnapshot.WSBaseURL))
	} else {
		log.Printf("agentws: connected to %s", websocketOriginForLog(identitySnapshot.WSBaseURL))
	}
	return resp, nil
}

// Connect dials the hub WebSocket endpoint. Wraps connectWithResponse,
// discarding the HTTP response.
func (t *wsTransport) Connect(ctx context.Context) error {
	_, err := t.connectWithResponse(ctx)
	return err
}

// pingLoop sends periodic WebSocket pings to the hub. It exits when the done
// channel is closed or when the connection changes (reconnect replaces conn).
func (t *wsTransport) pingLoop(conn *websocket.Conn, done chan struct{}) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("agentws: panic in pingLoop: %v\n%s", err, debug.Stack())
		}
	}()
	ticker := time.NewTicker(clientPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			t.mu.Lock()
			if t.conn != conn {
				t.mu.Unlock()
				return
			}
			err := conn.WriteControl(
				websocket.PingMessage, nil,
				time.Now().Add(10*time.Second),
			)
			t.mu.Unlock()
			if err != nil {
				log.Printf("agentws: ping send failed: %v", err)
				t.markDisconnected()
				return
			}
		}
	}
}

func (t *wsTransport) Send(msg protocol.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return errNotConnected
	}
	// A tokenless socket is an enrollment-only control channel. The hub's
	// pending-enrollment state machine accepts exactly enrollment.proof; sending
	// heartbeat, telemetry, capabilities, or settings before approval is both a
	// protocol violation and an opportunity for unauthenticated data injection.
	if t.pendingEnrollment && msg.Type != protocol.MsgEnrollmentProof {
		return errEnrollmentPending
	}
	// Apply a write deadline so that a slow or unresponsive hub cannot block
	// Send indefinitely while holding t.mu. Without this, heartbeat, telemetry,
	// VNC, terminal, and Docker-event goroutines would all serialize and stall
	// behind a single slow write.
	_ = t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := t.conn.WriteJSON(msg)
	if err == nil {
		atomic.AddInt64(&t.messagesSent, 1)
	}
	return err
}

func (t *wsTransport) Receive() (protocol.Message, error) {
	msg, _, err := t.receiveWithEnrollmentState()
	return msg, err
}

// receiveWithEnrollmentState binds the authentication state to the exact
// socket a message was read from. A pending socket can be disconnected while
// its final messages are being drained, so consulting the transport's current
// state after ReadJSON would create a race where an unauthenticated message
// could be dispatched as ordinary hub traffic.
func (t *wsTransport) receiveWithEnrollmentState() (protocol.Message, bool, error) {
	t.mu.Lock()
	conn := t.conn
	pendingEnrollment := t.pendingEnrollment
	t.mu.Unlock()
	if conn == nil {
		return protocol.Message{}, pendingEnrollment, errNotConnected
	}

	var msg protocol.Message
	err := conn.ReadJSON(&msg)
	if err == nil {
		atomic.AddInt64(&t.messagesReceived, 1)
	}
	return msg, pendingEnrollment, err
}

func (t *wsTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pingDone != nil {
		close(t.pingDone)
		t.pingDone = nil
	}
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	t.connected = false
	t.pendingEnrollment = false
}

// socketOpen reports whether a pending or authenticated WebSocket is open.
// It is intentionally internal to transport lifecycle/read loops; product
// readiness and publishers must use Connected, which is authenticated-only.
func (t *wsTransport) socketOpen() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

// EnrollmentPending reports whether the transport is holding a tokenless
// enrollment-control socket. Such a socket remains readable for challenge and
// approval messages, but is not ordinary product connectivity.
func (t *wsTransport) EnrollmentPending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && t.pendingEnrollment
}

func (t *wsTransport) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && !t.pendingEnrollment
}

// ConnectionState returns a human-readable connection state plus the last error
// string and the time the transport was first disconnected.
func (t *wsTransport) ConnectionState() (state string, lastErr string, disconnectedAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// A token explicitly rejected by the enrollment endpoint is terminal for
	// this setup attempt. Do not let the fallback pending socket make local UI
	// report an indefinite generic "connecting" state.
	if t.credentialError != "" {
		return "auth_failed", t.credentialError, t.disconnectedAt
	}
	if t.connected {
		if t.pendingEnrollment {
			return "connecting", enrollmentPendingState, time.Time{}
		}
		return "connected", t.credentialPersistenceError, time.Time{}
	}
	if t.lastError == "auth_failed" {
		return "auth_failed", t.lastError, t.disconnectedAt
	}
	if t.lastError != "" {
		return "connecting", t.lastError, t.disconnectedAt
	}
	if t.credentialPersistenceError != "" {
		return "connecting", t.credentialPersistenceError, t.disconnectedAt
	}
	return "disconnected", "", t.disconnectedAt
}

func (t *wsTransport) markDisconnected() {
	t.mu.Lock()
	t.connected = false
	t.pendingEnrollment = false
	if t.pingDone != nil {
		close(t.pingDone)
		t.pingDone = nil
	}
	if t.disconnectedAt.IsZero() {
		t.disconnectedAt = time.Now().UTC()
	}
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	t.mu.Unlock()
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

// Stats returns a snapshot of the transport's diagnostic counters and uptime.
// All counter reads use atomic loads and are safe to call from any goroutine.
func (t *wsTransport) Stats() (sent, received, reconnects int64, uptime time.Duration) {
	return atomic.LoadInt64(&t.messagesSent),
		atomic.LoadInt64(&t.messagesReceived),
		atomic.LoadInt64(&t.reconnectCount),
		time.Since(t.startedAt)
}

type errNotConnectedType struct{}

func (errNotConnectedType) Error() string { return "websocket not connected" }

var errNotConnected error = errNotConnectedType{}

type errEnrollmentPendingType struct{}

func (errEnrollmentPendingType) Error() string { return enrollmentPendingState }

const enrollmentPendingState = "enrollment_pending"

var errEnrollmentPending error = errEnrollmentPendingType{}

var errRuntimeIdentityChanged = errors.New("runtime identity changed during websocket connection")

func validateWebSocketTransportURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("websocket url is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("invalid websocket url")
	}
	if parsed.User != nil {
		return fmt.Errorf("websocket url must not contain user info")
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "wss":
		return nil
	case "ws":
		if allowInsecureTransportOptIn() {
			return nil
		}
		return fmt.Errorf("insecure websocket scheme requires %s=true", envAllowInsecureTransport)
	default:
		return fmt.Errorf("unsupported websocket scheme %q", parsed.Scheme)
	}
}

func websocketOriginForLog(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return "configured hub"
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host
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
