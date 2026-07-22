package agentcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labtether/labtether-agent/internal/assets"
	"github.com/labtether/protocol"
)

func TestRuntimeIdentityConcurrentSnapshotsRemainCoherent(t *testing.T) {
	identity := newRuntimeIdentitySource(RuntimeConfig{
		APIToken:   "token-a",
		AssetID:    "asset-a",
		WSBaseURL:  "wss://hub-a.example.test/ws/agent",
		APIBaseURL: "https://hub-a.example.test",
	})

	type credentialSet struct {
		token string
		asset string
		ws    string
		api   string
	}
	sets := []credentialSet{
		{"token-a", "asset-a", "wss://hub-a.example.test/ws/agent", "https://hub-a.example.test"},
		{"token-b", "asset-b", "wss://hub-b.example.test/ws/agent", "https://hub-b.example.test"},
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	recordErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				set := sets[(i+offset)%len(sets)]
				if _, err := identity.AdoptCredential(set.token, set.asset, set.ws, set.api); err != nil {
					recordErr(err)
					return
				}
			}
		}(writer)
	}
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 4000; i++ {
				snapshot := identity.Snapshot()
				coherent := false
				for _, set := range sets {
					if snapshot.BearerToken == set.token && snapshot.AssetID == set.asset && snapshot.WSBaseURL == set.ws && snapshot.APIBaseURL == set.api {
						coherent = true
						break
					}
				}
				if !coherent {
					recordErr(errors.New("observed a mixed runtime identity snapshot"))
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func TestRuntimeIdentityRejectsStaleHandshakeCanonicalization(t *testing.T) {
	identity := newRuntimeIdentitySource(RuntimeConfig{
		APIToken:   "old-token",
		AssetID:    "old-asset",
		WSBaseURL:  "wss://old.example.test/ws/agent",
		APIBaseURL: "https://old.example.test",
	})
	staleHandshake := identity.Snapshot()
	if _, err := identity.AdoptCredential("new-token", "new-asset", "wss://new.example.test/ws/agent", "https://new.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, applied, err := identity.AdoptCanonicalAsset(staleHandshake, "stale-canonical-asset"); err != nil {
		t.Fatal(err)
	} else if applied {
		t.Fatal("stale handshake overwrote a newer credential rotation")
	}
	snapshot := identity.Snapshot()
	if snapshot.BearerToken != "new-token" || snapshot.AssetID != "new-asset" || snapshot.APIBaseURL != "https://new.example.test" {
		t.Fatal("new runtime identity was not preserved")
	}
}

func TestIssuedAgentCredentialValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		token string
		valid bool
	}{
		{name: "base64url", token: "Abc_123-xyz", valid: true},
		{name: "bearer padding", token: "abc+/=", valid: true},
		{name: "whitespace trimmed", token: "  token-value  ", valid: true},
		{name: "embedded whitespace", token: "token value"},
		{name: "header newline", token: "token\nforged"},
		{name: "oversized", token: strings.Repeat("a", maxAgentBearerTokenBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeIssuedAgentToken(test.token)
			if test.valid && (err != nil || got == "") {
				t.Fatalf("valid credential rejected: token=%q err=%v", got, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("invalid credential accepted: %q", got)
			}
		})
	}
}

func TestRotatedIdentityDrivesDisconnectedHTTPFallback(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	type receivedHeartbeat struct {
		authorization string
		payload       assets.HeartbeatRequest
	}
	received := make(chan receivedHeartbeat, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload assets.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode heartbeat: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- receivedHeartbeat{authorization: r.Header.Get("Authorization"), payload: payload}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	identity := newRuntimeIdentitySource(RuntimeConfig{
		APIToken:   "old-token",
		AssetID:    "old-asset",
		WSBaseURL:  "ws://old.invalid/ws/agent",
		APIBaseURL: "http://old.invalid",
	})
	cfg := RuntimeConfig{Name: "labtether-agent", Source: "agent"}
	fallback := newHeartbeatPublisherWithRuntimeIdentity(cfg, nil, identity)
	transport := newWSTransportWithRuntimeIdentity(identity, "linux", "test", nil, "", nil)
	publisher := newWSHeartbeatPublisher(transport, fallback, cfg, map[string]string{"platform": "linux"}, nil)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/agent"
	if _, err := identity.AdoptCredential("new-token", "new-asset", wsURL, server.URL); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(context.Background(), TelemetrySample{AssetID: "stale-sample-asset"}); err != nil {
		t.Fatalf("publish through rotated fallback: %v", err)
	}

	select {
	case got := <-received:
		if got.authorization != "Bearer new-token" {
			t.Fatalf("fallback did not use the current bearer")
		}
		if got.payload.AssetID != "new-asset" || got.payload.Name != "new-asset" {
			t.Fatalf("fallback heartbeat identity=%q/%q, want new-asset", got.payload.AssetID, got.payload.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fallback heartbeat")
	}
}

func TestPendingApprovalActivatesPreviouslyCredentiallessFallback(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	received := make(chan assets.HeartbeatRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer approved-token" {
			t.Error("fallback request did not use approved bearer")
		}
		var payload assets.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode heartbeat: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/agent"
	identity := newRuntimeIdentitySource(RuntimeConfig{
		AssetID:    "pending-asset",
		WSBaseURL:  wsURL,
		APIBaseURL: server.URL,
	})
	cfg := RuntimeConfig{Name: "labtether-agent", Source: "agent"}
	fallback := newHeartbeatPublisherWithRuntimeIdentity(cfg, nil, identity)
	transport := newWSTransportWithRuntimeIdentity(identity, "linux", "test", nil, "", nil)
	publisher := newWSHeartbeatPublisher(transport, fallback, cfg, nil, nil)

	if err := publisher.Publish(context.Background(), TelemetrySample{AssetID: "pending-asset"}); !errors.Is(err, errHeartbeatCredentialsUnavailable) {
		t.Fatalf("credentialless fallback error=%v, want unavailable", err)
	}
	approvedPayload, err := json.Marshal(protocol.EnrollmentApprovedData{Token: "approved-token", AssetID: "canonical-approved-asset"})
	if err != nil {
		t.Fatal(err)
	}
	handleEnrollmentApproved(transport, protocol.Message{Type: protocol.MsgEnrollmentApproved, Data: approvedPayload}, RuntimeConfig{})

	if err := publisher.Publish(context.Background(), TelemetrySample{AssetID: "stale-sample-asset"}); err != nil {
		t.Fatalf("approved fallback publish: %v", err)
	}
	select {
	case payload := <-received:
		if payload.AssetID != "canonical-approved-asset" {
			t.Fatalf("approved fallback asset_id=%q", payload.AssetID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for approved fallback heartbeat")
	}
	snapshot := identity.Snapshot()
	if snapshot.AssetID != "canonical-approved-asset" || snapshot.APIBaseURL != server.URL || snapshot.WSBaseURL != wsURL {
		t.Fatal("pending approval did not atomically retain current origins")
	}
}

func TestCanonicalIdentityReachesLocalAndBufferedTelemetryImmediately(t *testing.T) {
	identity := newRuntimeIdentitySource(RuntimeConfig{
		APIToken:   "token",
		AssetID:    "startup-asset",
		WSBaseURL:  "wss://hub.example.test/ws/agent",
		APIBaseURL: "https://hub.example.test",
	})
	runtime := newRuntimeWithIdentity(RuntimeConfig{Name: "agent", AssetID: "startup-asset"}, nil, &recordingHeartbeatPublisher{}, identity)
	runtime.mu.Lock()
	runtime.sample = TelemetrySample{AssetID: "startup-asset", CPUPercent: 42, CollectedAt: time.Now().UTC()}
	runtime.mu.Unlock()

	handshake := identity.Snapshot()
	if _, applied, err := identity.AdoptCanonicalAsset(handshake, "canonical-asset"); err != nil {
		t.Fatal(err)
	} else if !applied {
		t.Fatal("canonical handshake identity was not applied")
	}

	req := httptest.NewRequest(http.MethodGet, "/agent/status", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	runtime.statusHandler()(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", rec.Code, rec.Body.String())
	}
	var status StatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.AssetID != "canonical-asset" || status.Metrics.AssetID != "canonical-asset" {
		t.Fatalf("local status identity=%q metrics=%q", status.AssetID, status.Metrics.AssetID)
	}

	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	transport.runtimeIdentity = identity
	telemetryBuf := NewRingBuffer[TelemetrySample](2)
	telemetryBuf.Push(TelemetrySample{AssetID: "startup-asset", CPUPercent: 17})
	replayBufferedTelemetry(transport, telemetryBuf)
	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgTelemetry, 2*time.Second)
	var telemetry protocol.TelemetryData
	if err := json.Unmarshal(msg.Data, &telemetry); err != nil {
		t.Fatal(err)
	}
	if telemetry.AssetID != "canonical-asset" {
		t.Fatalf("replayed telemetry asset_id=%q", telemetry.AssetID)
	}
	transport.mu.Lock()
	transport.connected = true
	transport.mu.Unlock()
	wsPublisher := newWSHeartbeatPublisher(transport, nil, RuntimeConfig{Source: "agent"}, map[string]string{"platform": "linux"}, nil)
	if err := wsPublisher.Publish(context.Background(), TelemetrySample{AssetID: "startup-asset"}); err != nil {
		t.Fatal(err)
	}
	heartbeatMessage := waitForCapturedAgentMessage(t, messages, protocol.MsgHeartbeat, 2*time.Second)
	var heartbeat protocol.HeartbeatData
	if err := json.Unmarshal(heartbeatMessage.Data, &heartbeat); err != nil {
		t.Fatal(err)
	}
	if heartbeat.AssetID != "canonical-asset" || heartbeat.Name != "canonical-asset" {
		t.Fatalf("websocket heartbeat identity=%q/%q", heartbeat.AssetID, heartbeat.Name)
	}
}

func TestWSTransportConnectReadsLatestRuntimeIdentitySnapshot(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")

	headers := make(chan http.Header, 1)
	done := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	identity := newRuntimeIdentitySource(RuntimeConfig{
		APIToken:   "old-token",
		AssetID:    "old-asset",
		WSBaseURL:  "ws://127.0.0.1:1/ws/agent",
		APIBaseURL: "http://127.0.0.1:1",
	})
	transport := newWSTransportWithRuntimeIdentity(identity, "linux", "test", nil, "", nil)
	newWSURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/agent"
	if _, err := identity.AdoptCredential("new-token", "new-asset", newWSURL, server.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.connectWithResponse(context.Background()); err != nil {
		t.Fatalf("connect with latest identity: %v", err)
	}
	defer transport.Close()

	select {
	case header := <-headers:
		if header.Get("Authorization") != "Bearer new-token" || header.Get("X-Asset-ID") != "new-asset" {
			t.Fatal("websocket handshake did not use one current identity snapshot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket handshake")
	}
}
