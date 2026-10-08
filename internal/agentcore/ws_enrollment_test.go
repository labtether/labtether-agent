package agentcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/labtether/labtether-agent/internal/agentidentity"
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectWithResponseSendsBearerTokenHeaders(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")

	headersSeen := make(chan http.Header, 1)
	done := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersSeen <- r.Header.Clone()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer conn.Close()
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	transport := newWSTransport("ws"+server.URL[len("http"):], "token-123", "node-01", "linux", "v1.2.3", nil, "", nil)
	defer transport.Close()

	resp, err := transport.connectWithResponse(context.Background())
	if err != nil {
		t.Fatalf("connectWithResponse returned error: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if !transport.Connected() {
		t.Fatalf("expected transport to be marked connected")
	}
	if transport.EnrollmentPending() {
		t.Fatal("authenticated transport reported enrollment pending")
	}
	if state, lastErr, _ := transport.ConnectionState(); state != "connected" || lastErr != "" {
		t.Fatalf("authenticated connection state=(%q,%q)", state, lastErr)
	}

	select {
	case headers := <-headersSeen:
		if got := headers.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("expected Authorization header, got %q", got)
		}
		if got := headers.Get("X-Asset-ID"); got != "node-01" {
			t.Fatalf("expected X-Asset-ID header, got %q", got)
		}
		if got := headers.Get("X-Platform"); got != "linux" {
			t.Fatalf("expected X-Platform header, got %q", got)
		}
		if got := headers.Get("X-Agent-Version"); got != "v1.2.3" {
			t.Fatalf("expected X-Agent-Version header, got %q", got)
		}
		if got := headers.Get("X-Request-Enrollment"); got != "" {
			t.Fatalf("expected no enrollment header when token is present, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket request headers")
	}
}

func TestConnectWithResponseAdoptsAndPersistsTokenBoundAssetID(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")

	headersSeen := make(chan http.Header, 1)
	done := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersSeen <- r.Header.Clone()
		responseHeaders := http.Header{}
		responseHeaders.Set("X-LabTether-Asset-ID", "canonical-node")
		conn, err := upgrader.Upgrade(w, r, responseHeaders)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer conn.Close()
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	tokenFilePath := filepath.Join(t.TempDir(), "agent-token")
	transport := newWSTransport(
		"ws"+server.URL[len("http"):],
		"token-123",
		"stale-display-name",
		"linux",
		"v1.2.3",
		nil,
		tokenFilePath,
		nil,
	)
	defer transport.Close()

	resp, err := transport.connectWithResponse(context.Background())
	if err != nil {
		t.Fatalf("connectWithResponse returned error: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if got := transport.AssetID(); got != "canonical-node" {
		t.Fatalf("transport asset ID=%q, want canonical-node", got)
	}

	select {
	case headers := <-headersSeen:
		if got := headers.Get("X-Asset-ID"); got != "stale-display-name" {
			t.Fatalf("initial X-Asset-ID=%q, want stale-display-name", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket request headers")
	}

	cfg := RuntimeConfig{TokenFilePath: tokenFilePath}
	if err := restoreEnrollmentState(&cfg); err != nil {
		t.Fatalf("restore persisted enrollment state: %v", err)
	}
	if cfg.AssetID != "canonical-node" {
		t.Fatalf("persisted asset ID=%q, want canonical-node", cfg.AssetID)
	}
	identity := transport.identitySource().Snapshot()
	if cfg.WSBaseURL != identity.WSBaseURL || cfg.APIBaseURL != apiBaseURLFromWS(identity.WSBaseURL) {
		t.Fatalf("persisted endpoints ws=%q api=%q", cfg.WSBaseURL, cfg.APIBaseURL)
	}
}

func TestConnectWithResponseRequestsEnrollmentWhenTokenEmpty(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device identity: %v", err)
	}
	identity := &deviceIdentity{
		KeyAlgorithm:    agentidentity.KeyAlgorithmEd25519,
		PublicKey:       publicKey,
		PrivateKey:      privateKey,
		PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey),
		Fingerprint:     agentidentity.FingerprintFromPublicKey(publicKey),
	}

	headersSeen := make(chan http.Header, 1)
	messagesSeen := make(chan protocol.Message, 1)
	serverErrors := make(chan error, 1)
	done := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersSeen <- r.Header.Clone()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		defer conn.Close()
		challengeData, err := json.Marshal(protocol.EnrollmentChallengeData{
			ConnectionID: "pending-test-node-connection",
			Nonce:        "pending-test-nonce",
		})
		if err != nil {
			serverErrors <- err
			return
		}
		if err := conn.WriteJSON(protocol.Message{
			Type: protocol.MsgEnrollmentChallenge,
			Data: challengeData,
		}); err != nil {
			serverErrors <- err
			return
		}
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			serverErrors <- err
			return
		}
		messagesSeen <- msg
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	transport := newWSTransport(
		"ws"+server.URL[len("http"):],
		"",
		"pending-node-01",
		"linux",
		"v1.2.3",
		nil,
		"",
		identity,
	)
	defer transport.Close()

	resp, err := transport.connectWithResponse(context.Background())
	if err != nil {
		t.Fatalf("connectWithResponse returned error: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if transport.Connected() {
		t.Fatal("pending enrollment socket reported ordinary connectivity")
	}
	if !transport.EnrollmentPending() || !transport.socketOpen() {
		t.Fatal("expected an open pending-enrollment control socket")
	}
	state, lastErr, disconnectedAt := transport.ConnectionState()
	if state != "connecting" || lastErr != enrollmentPendingState || !disconnectedAt.IsZero() {
		t.Fatalf("pending connection state=(%q,%q,%v)", state, lastErr, disconnectedAt)
	}

	// Normal runtime traffic must be rejected locally; otherwise the strict Hub
	// closes the pending socket before the receive loop can answer its challenge.
	if err := transport.Send(protocol.Message{
		Type: protocol.MsgHeartbeat,
		Data: json.RawMessage(`{}`),
	}); !errors.Is(err, errEnrollmentPending) {
		t.Fatalf("pending heartbeat error=%v, want %v", err, errEnrollmentPending)
	}

	challenge, err := transport.Receive()
	if err != nil {
		t.Fatalf("read pending enrollment challenge: %v", err)
	}
	if challenge.Type != protocol.MsgEnrollmentChallenge {
		t.Fatalf("pending message type=%q, want %q", challenge.Type, protocol.MsgEnrollmentChallenge)
	}
	handleEnrollmentChallenge(transport, challenge, RuntimeConfig{})

	select {
	case headers := <-headersSeen:
		if got := headers.Get("Authorization"); got != "" {
			t.Fatalf("expected no Authorization header in enrollment mode, got %q", got)
		}
		if got := headers.Get("X-Request-Enrollment"); got != "true" {
			t.Fatalf("expected enrollment header, got %q", got)
		}
		if got := headers.Get("X-Asset-ID"); got != "pending-node-01" {
			t.Fatalf("expected X-Asset-ID header, got %q", got)
		}
		if got := headers.Get("X-Device-Key-Alg"); got != "ed25519" {
			t.Fatalf("expected X-Device-Key-Alg header, got %q", got)
		}
		if got := headers.Get("X-Device-Public-Key"); got != identity.PublicKeyBase64 {
			t.Fatalf("expected X-Device-Public-Key header, got %q", got)
		}
		if got := headers.Get("X-Device-Fingerprint"); got != identity.Fingerprint {
			t.Fatalf("expected X-Device-Fingerprint header, got %q", got)
		}
		if got := headers.Get("X-Hostname"); got == "" {
			t.Fatalf("expected X-Hostname header to be set")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket request headers")
	}

	select {
	case err := <-serverErrors:
		t.Fatalf("pending enrollment server failed: %v", err)
	case proof := <-messagesSeen:
		if proof.Type != protocol.MsgEnrollmentProof {
			t.Fatalf("first pending client message=%q, want %q", proof.Type, protocol.MsgEnrollmentProof)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for enrollment proof")
	}
}

func TestReconnectLoopSkipsOnConnectUntilAuthenticatedReconnect(t *testing.T) {
	transport := &wsTransport{
		runtimeIdentity: newRuntimeIdentitySource(RuntimeConfig{}),
		timeAfter: func(d time.Duration) <-chan time.Time {
			if d > 5*time.Millisecond {
				d = 5 * time.Millisecond
			}
			return time.After(d)
		},
	}
	pendingConnected := make(chan struct{})
	connectCalls := 0
	transport.connectWithResponseFn = func(context.Context) (*http.Response, error) {
		connectCalls++
		transport.mu.Lock()
		transport.connected = true
		transport.pendingEnrollment = connectCalls == 1
		transport.mu.Unlock()
		if connectCalls == 1 {
			close(pendingConnected)
		}
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var onConnectCalls atomic.Int32
	go func() {
		transport.reconnectLoop(ctx, func() {
			onConnectCalls.Add(1)
			transport.markDisconnected()
			cancel()
		})
		close(done)
	}()

	select {
	case <-pendingConnected:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pending connection")
	}
	select {
	case <-done:
		t.Fatal("reconnect loop exited while pending")
	case <-time.After(25 * time.Millisecond):
	}
	if got := onConnectCalls.Load(); got != 0 {
		t.Fatalf("onConnect ran %d times for pending socket", got)
	}
	transport.markDisconnected()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for authenticated reconnect")
	}
	if connectCalls != 2 {
		t.Fatalf("connect calls=%d, want 2", connectCalls)
	}
	if got := onConnectCalls.Load(); got != 1 {
		t.Fatalf("onConnect calls=%d, want authenticated reconnect only", got)
	}
}

func TestReconnectLoopReEnrollsAfterAuthFailureThreshold(t *testing.T) {
	waits := make(chan time.Duration, 4)
	transport := &wsTransport{
		runtimeIdentity: newRuntimeIdentitySource(RuntimeConfig{APIToken: "stale-token"}),
		timeAfter: func(d time.Duration) <-chan time.Time {
			waits <- d
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch
		},
		now:    func() time.Time { return time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC) },
		jitter: func(time.Duration) time.Duration { return 0 },
	}

	connectCalls := 0
	transport.connectWithResponseFn = func(context.Context) (*http.Response, error) {
		connectCalls++
		if connectCalls <= authFailureThreshold {
			return &http.Response{StatusCode: http.StatusUnauthorized}, errors.New("websocket: bad handshake")
		}
		transport.mu.Lock()
		transport.connected = true
		transport.consecutiveAuthFailures = 0
		transport.lastError = ""
		transport.mu.Unlock()
		return nil, nil
	}

	reEnrollCalls := 0
	transport.reEnrollFn = func() (string, error) {
		reEnrollCalls++
		return "fresh-token", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		transport.reconnectLoop(ctx, func() {
			transport.markDisconnected()
			cancel()
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconnect loop to exit")
	}

	if reEnrollCalls != 1 {
		t.Fatalf("expected one re-enrollment attempt, got %d", reEnrollCalls)
	}
	if connectCalls != authFailureThreshold+1 {
		t.Fatalf("expected %d connect attempts, got %d", authFailureThreshold+1, connectCalls)
	}
	if got := transport.identitySource().Snapshot().BearerToken; got != "fresh-token" {
		t.Fatalf("expected token to be refreshed, got %q", got)
	}
	if got := atomic.LoadInt64(&transport.reconnectCount); got != 1 {
		t.Fatalf("expected reconnect count 1, got %d", got)
	}

	gotWaits := []time.Duration{<-waits, <-waits}
	wantWaits := []time.Duration{time.Second, 2 * time.Second}
	for i := range wantWaits {
		if gotWaits[i] != wantWaits[i] {
			t.Fatalf("wait[%d] = %s, want %s", i, gotWaits[i], wantWaits[i])
		}
	}
	select {
	case extra := <-waits:
		t.Fatalf("unexpected extra wait duration %s", extra)
	default:
	}
}

func TestReconnectLoopForcesReconnectOnNetworkChange(t *testing.T) {
	networkChanged := make(chan struct{}, 1)
	transport := &wsTransport{
		networkChanged: networkChanged,
	}

	connectCalls := 0
	transport.connectWithResponseFn = func(context.Context) (*http.Response, error) {
		connectCalls++
		transport.mu.Lock()
		transport.connected = true
		transport.mu.Unlock()
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var onConnectCalls int32
	go func() {
		transport.reconnectLoop(ctx, func() {
			switch atomic.AddInt32(&onConnectCalls, 1) {
			case 1:
				networkChanged <- struct{}{}
			case 2:
				transport.markDisconnected()
				cancel()
			}
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconnect loop to exit")
	}

	if connectCalls != 2 {
		t.Fatalf("expected 2 connect attempts, got %d", connectCalls)
	}
	if got := atomic.LoadInt32(&onConnectCalls); got != 2 {
		t.Fatalf("expected onConnect to fire twice, got %d", got)
	}
	if got := atomic.LoadInt64(&transport.reconnectCount); got != 2 {
		t.Fatalf("expected reconnect count 2, got %d", got)
	}
}
