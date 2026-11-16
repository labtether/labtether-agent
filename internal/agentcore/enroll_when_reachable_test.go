package agentcore

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labtether/labtether-agent/internal/agentidentity"
)

const usedTokenWords = "This enrollment token was already used. Make a new one in Devices, Add device."

// lateHub is a stand-in Hub that starts listening only when the test says
// so, on an address reserved before the agent starts.
type lateHub struct {
	t            *testing.T
	addr         string
	identity     *deviceIdentity
	enrollStatus atomic.Int32 // the answer to POST /api/v1/enroll
	onPending    func()       // called for each socket without a token
	secure       bool         // serves https and wss; set before the agent starts
	caPEM        string       // the CA in the enrollment answer

	mu         sync.Mutex
	server     *httptest.Server
	enrolls    []string // the enrollment token of each request
	pending    int      // sockets without a token
	authorized []string // Authorization headers of sockets with a token
	requests   []string // Authorization headers of other requests (heartbeats)
}

func newLateHub(t *testing.T, identity *deviceIdentity) *lateHub {
	t.Helper()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := &lateHub{t: t, addr: reserved.Addr().String(), identity: identity}
	_ = reserved.Close()
	t.Cleanup(func() {
		hub.mu.Lock()
		server := hub.server
		hub.mu.Unlock()
		if server != nil {
			server.Close()
		}
	})
	return hub
}

func (h *lateHub) wsURL() string {
	if h.secure {
		return "wss://" + h.addr + "/ws/agent"
	}
	return "ws://" + h.addr + "/ws/agent"
}

func (h *lateHub) apiURL() string {
	if h.secure {
		return "https://" + h.addr
	}
	return "http://" + h.addr
}

// listen starts the Hub. It runs on the reconnect loop's goroutine, so it
// reports problems with Errorf.
func (h *lateHub) listen() { h.serve(nil) }

// serve starts the Hub, with serverTLS when the Hub is secure.
func (h *lateHub) serve(serverTLS *tls.Config) {
	listener, err := net.Listen("tcp", h.addr)
	if err != nil {
		h.t.Errorf("listen on the reserved Hub address: %v", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/enroll", h.enroll)
	mux.HandleFunc("/ws/agent", h.socket)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.requests = append(h.requests, r.Header.Get("Authorization"))
		h.mu.Unlock()
	})
	server := httptest.NewUnstartedServer(mux)
	_ = server.Listener.Close()
	server.Listener = listener
	if serverTLS != nil {
		server.TLS = serverTLS
		server.StartTLS()
	} else {
		server.Start()
	}
	h.mu.Lock()
	h.server = server
	h.mu.Unlock()
}

// stop closes the Hub so another can listen on its address.
func (h *lateHub) stop() {
	h.mu.Lock()
	server := h.server
	h.server = nil
	h.mu.Unlock()
	if server != nil {
		server.Close()
	}
}

func (h *lateHub) enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.t.Errorf("decode enrollment request: %v", err)
	}
	h.mu.Lock()
	h.enrolls = append(h.enrolls, req.EnrollmentToken)
	h.mu.Unlock()
	// The late try sends what start-up sends: the v1 proof over the
	// configured asset ID.
	signature, _ := base64.StdEncoding.DecodeString(req.DeviceSignature)
	payload := agentidentity.BuildTokenEnrollmentProofPayload("nas01", req.EnrollmentToken, h.identity.Fingerprint)
	if req.Hostname != "nas01" || req.DeviceProofVersion != "v1" || !ed25519.Verify(h.identity.PublicKey, payload, signature) {
		h.t.Errorf("enrollment request hostname=%q proof=%q is not the start-up request", req.Hostname, req.DeviceProofVersion)
	}
	switch status := int(h.enrollStatus.Load()); status {
	case http.StatusOK:
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "issued-agent-token",
			AssetID:    "nas01",
			HubWSURL:   h.wsURL(),
			HubAPIURL:  h.apiURL(),
			CACertPEM:  h.caPEM,
		})
	case http.StatusUnauthorized:
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": usedTokenWords})
	default:
		w.WriteHeader(status)
	}
}

func (h *lateHub) socket(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	h.mu.Lock()
	if authorization == "" {
		h.pending++
	} else {
		h.authorized = append(h.authorized, authorization)
	}
	h.mu.Unlock()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	if authorization == "" && h.onPending != nil {
		h.onPending()
	}
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (h *lateHub) seen() (enrolls []string, pending int, authorized []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.enrolls...), h.pending, append([]string(nil), h.authorized...)
}

// startAgentWithoutHub loads the configuration and runs start-up enrollment
// as Run does, while nothing listens at the Hub address. It returns the
// transport and HTTP heartbeat fallback Run would build, with re-enrollment
// and late enrollment armed the same way.
func startAgentWithoutHub(t *testing.T, ctx context.Context, hub *lateHub, dir string) (RuntimeConfig, *wsTransport, HeartbeatPublisher) {
	t.Helper()
	cfg := LoadConfig("test-agent", "8090", "test")
	startErr := resolveTokenWithIdentity(ctx, &cfg, hub.identity)
	if startErr == nil || cfg.APIToken != "" {
		t.Fatalf("start-up enrollment without a Hub: err=%v token set=%v", startErr, cfg.APIToken != "")
	}
	if cfg.TLSSkipVerify && cfg.TLSCAFile != "" {
		cfg.TLSSkipVerify = false // Run: a configured CA takes priority
	}
	identity := newRuntimeIdentitySource(cfg)
	fallback := newHeartbeatPublisherWithRuntimeIdentity(cfg, nil, identity)
	transport := newWSTransportWithRuntimeIdentity(identity, "linux", "test", buildTLSConfig(&cfg), cfg.TokenFilePath, hub.identity)
	transport.jitter = func(time.Duration) time.Duration { return 0 }
	transport.reEnrollFn = func() (string, error) { return reEnrollAgainstActiveHub(ctx, cfg, transport) }
	if startEnrollmentUnanswered(cfg, startErr) {
		armEnrollmentWhenHubReachable(cfg, transport, fallback)
	}
	t.Cleanup(transport.Close)
	return cfg, transport, fallback
}

func lateHubAgent(t *testing.T) (*lateHub, string, string) {
	t.Helper()
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	dir := t.TempDir()
	enrollmentTokenFile := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(enrollmentTokenFile, []byte("late-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"LABTETHER_API_TOKEN":               "",
		"LABTETHER_ENROLLMENT_TOKEN":        "",
		"LABTETHER_API_BASE_URL":            "",
		"LABTETHER_TLS_CA_FILE":             "",
		"AGENT_ASSET_ID":                    "nas01",
		"LABTETHER_TOKEN_FILE":              filepath.Join(dir, "agent-token"),
		"LABTETHER_ENROLLMENT_TOKEN_FILE":   enrollmentTokenFile,
		"LABTETHER_AGENT_SETTINGS_FILE":     filepath.Join(dir, "agent-config.json"),
		"LABTETHER_DEVICE_KEY_FILE":         filepath.Join(dir, "device-key"),
		"LABTETHER_DEVICE_PUBLIC_KEY_FILE":  filepath.Join(dir, "device-key.pub"),
		"LABTETHER_DEVICE_FINGERPRINT_FILE": filepath.Join(dir, "device-fingerprint"),
	} {
		t.Setenv(name, value)
	}
	identity, err := ensureDeviceIdentity(LoadConfig("test-agent", "8090", "test"))
	if err != nil {
		t.Fatal(err)
	}
	hub := newLateHub(t, identity)
	t.Setenv("LABTETHER_WS_URL", hub.wsURL())
	return hub, dir, enrollmentTokenFile
}

func runLoopUntilStopped(t *testing.T, ctx context.Context, cancel context.CancelFunc, transport *wsTransport) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		// Stop once a socket with a token opens.
		transport.reconnectLoop(ctx, func() {
			transport.markDisconnected()
			cancel()
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("the reconnect loop did not stop")
	}
}

// Fault: an agent started while its Hub was down connected without its token
// once the Hub came back, so the Hub held it as a pending device for an admin
// to approve and the one-use token was never used. A 503 (a Hub down behind a
// proxy) is still "not there", not a refusal. After the late enrollment the
// token file is gone, which the Mac and Windows apps watch for, and a restart
// uses the saved agent token without enrolling again.
func TestStagedTokenEnrollsWhenHubComesBack(t *testing.T) {
	hub, dir, enrollmentTokenFile := lateHubAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub.onPending = cancel
	_, transport, _ := startAgentWithoutHub(t, ctx, hub, dir)

	var waits []time.Duration
	var stateWithoutHub []string
	transport.timeAfter = func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		switch len(waits) {
		case 1: // the first late try found no Hub; now it answers 503
			state, lastErr, _ := transport.ConnectionState()
			stateWithoutHub = []string{state, lastErr, transport.ConnectionErrorReason()}
			hub.enrollStatus.Store(http.StatusServiceUnavailable)
			hub.listen()
		case 2:
			hub.enrollStatus.Store(http.StatusOK)
		case 20:
			cancel()
		}
		ready := make(chan time.Time, 1)
		ready <- time.Now()
		return ready
	}
	runLoopUntilStopped(t, ctx, cancel, transport)

	enrolls, pending, authorized := hub.seen()
	if pending != 0 {
		t.Fatalf("the agent connected without its token %d time(s); it must enroll with it", pending)
	}
	if strings.Join(enrolls, ",") != "late-token,late-token" {
		t.Fatalf("enrollment requests after the Hub came back = %q, want the 503 then the accepted one", enrolls)
	}
	if strings.Join(authorized, ",") != "Bearer issued-agent-token" {
		t.Fatalf("sockets with a token = %q", authorized)
	}
	if want := []time.Duration{time.Second, 2 * time.Second}; len(waits) != 2 || waits[0] != want[0] || waits[1] != want[1] {
		t.Fatalf("waits = %v, want %v (the connect backoff)", waits, want)
	}
	if strings.Join(stateWithoutHub, "/") != "connecting/transient/"+connectReasonRefused {
		t.Fatalf("status while the Hub was down = %q", stateWithoutHub)
	}
	if token, _ := loadTokenFromFile(filepath.Join(dir, "agent-token")); token != "issued-agent-token" {
		t.Fatalf("saved agent token = %q", token)
	}
	if _, err := os.Stat(enrollmentTokenFile); !os.IsNotExist(err) {
		t.Fatalf("the used enrollment token file is still there: %v", err)
	}
	transport.mu.Lock()
	armed := transport.enrollFn != nil || transport.reEnrollFn != nil
	transport.mu.Unlock()
	if armed {
		t.Fatal("the spent token is still armed for enrollment or re-enrollment")
	}

	restart := LoadConfig("test-agent", "8090", "test")
	if err := resolveTokenWithIdentity(context.Background(), &restart, hub.identity); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if enrolls, _, _ := hub.seen(); restart.APIToken != "issued-agent-token" || len(enrolls) != 2 {
		t.Fatalf("restart: token set=%v enrollment requests=%d, want the saved token and no new request",
			restart.APIToken == "issued-agent-token", len(enrolls))
	}
}

// Fault: a token the Hub refuses once it is back (used, expired, revoked: all
// 401) is offered again on every reconnect, or the agent stops. As when the
// Hub refuses the token at start, the agent asks once, then connects as a
// pending device, shows the Hub's words on the status page and keeps the
// token for Go's existing re-enrollment.
func TestRefusedStagedTokenFallsBackToPendingOnce(t *testing.T) {
	hub, dir, enrollmentTokenFile := lateHubAgent(t)
	hub.enrollStatus.Store(http.StatusUnauthorized)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, transport, _ := startAgentWithoutHub(t, ctx, hub, dir)

	waitCalls, pendingSockets := 0, 0
	transport.timeAfter = func(time.Duration) <-chan time.Time {
		waitCalls++
		switch {
		case waitCalls == 1:
			hub.listen()
		case transport.EnrollmentPending():
			// The Hub drops the pending socket; the receive loop would
			// mark it closed. Stop after the third one.
			pendingSockets++
			if pendingSockets == 3 {
				cancel()
			}
			transport.markDisconnected()
		case waitCalls > 40:
			cancel()
		}
		ready := make(chan time.Time, 1)
		ready <- time.Now()
		return ready
	}
	runLoopUntilStopped(t, ctx, cancel, transport)

	enrolls, pending, authorized := hub.seen()
	if len(enrolls) != 1 || pending != 3 || len(authorized) != 0 {
		t.Fatalf("enrollment requests=%d pending sockets=%d sockets with a token=%d, want 1, 3, 0",
			len(enrolls), pending, len(authorized))
	}
	if state, lastErr, _ := transport.ConnectionState(); state != "auth_failed" || lastErr != enrollmentTokenRejected {
		t.Fatalf("status = %s/%s, want auth_failed/%s", state, lastErr, enrollmentTokenRejected)
	}
	if words := transport.EnrollmentRefusal(); words != usedTokenWords {
		t.Fatalf("refusal words = %q", words)
	}
	if _, err := os.Stat(enrollmentTokenFile); err != nil {
		t.Fatalf("a refused token file must stay: %v", err)
	}
	transport.mu.Lock()
	lateArmed, reEnrollArmed := transport.enrollFn != nil, transport.reEnrollFn != nil
	transport.mu.Unlock()
	if lateArmed || !reEnrollArmed {
		t.Fatalf("late enrollment armed=%v re-enrollment armed=%v, want false, true", lateArmed, reEnrollArmed)
	}
}
