package agentcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentidentity"
)

func TestReEnrollAgainstActiveHubBypassesStaleCredentialSources(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	wrongHubCalls := 0
	wrongHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		wrongHubCalls++
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "wrong-hub-token",
			AssetID:    "wrong-hub-asset",
		})
	}))
	defer wrongHub.Close()

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

	activeHubCalls := 0
	var activeHubURL string
	activeHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeHubCalls++
		if r.URL.Path != "/api/v1/enroll" {
			t.Errorf("enrollment path = %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode enrollment request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.EnrollmentToken != "fresh-enrollment-token" {
			t.Errorf("enrollment token = %q", req.EnrollmentToken)
		}
		if req.DeviceKeyAlg != agentidentity.KeyAlgorithmEd25519 || req.DeviceFingerprint != identity.Fingerprint || req.DevicePublicKey != identity.PublicKeyBase64 {
			t.Error("re-enrollment request is missing device continuity fields")
		}
		if req.DeviceProofVersion != "v2" {
			t.Errorf("device proof version = %q, want v2", req.DeviceProofVersion)
		}
		signature, decodeErr := base64.StdEncoding.DecodeString(req.DeviceSignature)
		if decodeErr != nil {
			t.Errorf("decode signature: %v", decodeErr)
		}
		proofPayload := agentidentity.BuildTokenEnrollmentProofPayloadV2("stale-container-vm", req.EnrollmentToken, identity.Fingerprint)
		if !ed25519.Verify(publicKey, proofPayload, signature) {
			t.Error("re-enrollment continuity proof did not verify")
		}
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "fresh-agent-token",
			AssetID:    "canonical-container-vm",
			HubWSURL:   strings.Replace(activeHubURL, "http://", "ws://", 1) + "/ws/agent",
			HubAPIURL:  activeHubURL,
		})
	}))
	defer activeHub.Close()
	activeHubURL = activeHub.URL

	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	if err := os.WriteFile(tokenFile, []byte("stale-agent-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enrollmentTokenFile := filepath.Join(filepath.Dir(tokenFile), "enrollment-token")
	if err := os.WriteFile(enrollmentTokenFile, []byte("fresh-enrollment-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	activeWSURL := strings.Replace(activeHub.URL, "http://", "ws://", 1) + "/ws/agent"
	transport := newWSTransport(activeWSURL, "stale-agent-token", "stale-container-vm", "linux", "test", nil, tokenFile, identity)
	transport.reEnrollFn = func() (string, error) { return "sentinel", nil }
	cfg := RuntimeConfig{
		AssetID:                 "stale-container-vm",
		APIToken:                "stale-explicit-token",
		EnrollmentToken:         "fresh-enrollment-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		APIBaseURL:              wrongHub.URL,
		WSBaseURL:               strings.Replace(wrongHub.URL, "http://", "ws://", 1) + "/ws/agent",
		TokenFilePath:           tokenFile,
	}

	token, err := reEnrollAgainstActiveHub(context.Background(), cfg, transport)
	if err != nil {
		t.Fatalf("re-enroll against active hub: %v", err)
	}
	if token != "fresh-agent-token" {
		t.Fatalf("token = %q", token)
	}
	if activeHubCalls != 1 || wrongHubCalls != 0 {
		t.Fatalf("active hub calls=%d wrong hub calls=%d", activeHubCalls, wrongHubCalls)
	}
	if got := transport.AssetID(); got != "canonical-container-vm" {
		t.Fatalf("transport asset id = %q", got)
	}
	runtimeIdentity := transport.identitySource().Snapshot()
	if runtimeIdentity.BearerToken != "fresh-agent-token" || runtimeIdentity.AssetID != "canonical-container-vm" || runtimeIdentity.WSBaseURL != activeWSURL || runtimeIdentity.APIBaseURL != activeHub.URL {
		t.Fatalf("runtime identity did not rotate atomically: token_current=%v asset=%q ws=%q api=%q", runtimeIdentity.BearerToken == "fresh-agent-token", runtimeIdentity.AssetID, runtimeIdentity.WSBaseURL, runtimeIdentity.APIBaseURL)
	}
	persistedToken, err := loadTokenFromFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if persistedToken != "fresh-agent-token" {
		t.Fatalf("persisted token = %q", persistedToken)
	}
	if _, err := os.Stat(enrollmentTokenFile); !os.IsNotExist(err) {
		t.Fatalf("consumed re-enrollment token file was not removed: %v", err)
	}
	transport.mu.Lock()
	reEnrollStillArmed := transport.reEnrollFn != nil
	transport.mu.Unlock()
	if reEnrollStillArmed {
		t.Fatal("re-enrollment callback remained armed after consuming the one-time token")
	}

	restored := RuntimeConfig{TokenFilePath: tokenFile}
	if err := restoreEnrollmentState(&restored); err != nil {
		t.Fatalf("restore enrollment state: %v", err)
	}
	if restored.AssetID != "canonical-container-vm" || restored.WSBaseURL != activeWSURL {
		t.Fatalf("restored enrollment state = %#v", restored)
	}
}

func TestReEnrollPersistenceFailureRemovesStaleTokenAndSurfacesStatus(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	activeHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "memory-only-replacement",
			AssetID:    "persistence-failure-node",
		})
	}))
	defer activeHub.Close()

	tmpDir := t.TempDir()
	blockingParent := filepath.Join(tmpDir, "not-a-directory")
	if err := os.WriteFile(blockingParent, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(blockingParent, "agent-token")
	enrollmentTokenFile := filepath.Join(tmpDir, "enrollment-token")
	if err := os.WriteFile(enrollmentTokenFile, []byte("fresh-enrollment-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	activeWSURL := strings.Replace(activeHub.URL, "http://", "ws://", 1) + "/ws/agent"
	transport := newWSTransport(activeWSURL, "revoked-token", "persistence-failure-node", "linux", "test", nil, tokenFile, nil)
	transport.reEnrollFn = func() (string, error) { return "sentinel", nil }
	cfg := RuntimeConfig{
		EnrollmentToken:         "fresh-enrollment-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		TokenFilePath:           tokenFile,
	}

	token, err := reEnrollAgainstActiveHub(context.Background(), cfg, transport)
	if err != nil {
		t.Fatalf("re-enroll with persistence failure: %v", err)
	}
	if token != "memory-only-replacement" {
		t.Fatalf("in-memory replacement token=%q", token)
	}
	runtimeIdentity := transport.identitySource().Snapshot()
	if runtimeIdentity.BearerToken != "memory-only-replacement" || runtimeIdentity.AssetID != "persistence-failure-node" || runtimeIdentity.WSBaseURL != activeWSURL || runtimeIdentity.APIBaseURL != activeHub.URL {
		t.Fatalf("memory-only runtime identity is incomplete: token_current=%v asset=%q ws=%q api=%q", runtimeIdentity.BearerToken == "memory-only-replacement", runtimeIdentity.AssetID, runtimeIdentity.WSBaseURL, runtimeIdentity.APIBaseURL)
	}
	if _, statErr := os.Stat(tokenFile); statErr == nil {
		t.Fatalf("stale token target remained: %v", statErr)
	}
	if _, statErr := os.Stat(enrollmentTokenFile); !os.IsNotExist(statErr) {
		t.Fatalf("consumed re-enrollment token remained: %v", statErr)
	}
	transport.mu.Lock()
	reEnrollStillArmed := transport.reEnrollFn != nil
	transport.mu.Unlock()
	if reEnrollStillArmed {
		t.Fatal("re-enrollment callback remained armed")
	}
	state, lastErr, _ := transport.ConnectionState()
	if state != "connecting" || lastErr != "agent_token_persistence_failed" {
		t.Fatalf("connection status=(%q, %q), want visible persistence failure", state, lastErr)
	}
}
