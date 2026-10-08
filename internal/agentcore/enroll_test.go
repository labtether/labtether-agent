package agentcore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/labtether/labtether-agent/internal/agentidentity"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCACertPEM generates a real self-signed CA certificate for testing.
func testCACertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestResolveToken_ExplicitAPIToken(t *testing.T) {
	cfg := &RuntimeConfig{
		APIToken:  "existing-token",
		WSBaseURL: "wss://hub.example.test:8443/ws/agent",
	}
	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "existing-token" {
		t.Fatalf("expected token unchanged, got %q", cfg.APIToken)
	}
	if cfg.APIBaseURL != "https://hub.example.test:8443" {
		t.Fatalf("APIBaseURL=%q, want active WS origin", cfg.APIBaseURL)
	}
}

func TestResolveToken_EnrollmentFlow(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	// Mock enrollment server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.EnrollmentToken != "test-enroll-token" {
			t.Errorf("expected enrollment_token=test-enroll-token, got %q", req.EnrollmentToken)
		}
		if req.Hostname != "configured-enrollment-node" {
			t.Errorf("expected configured asset ID as enrollment hostname, got %q", req.Hostname)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "new-agent-token",
			AssetID:    req.Hostname,
			HubWSURL:   "ws://localhost/ws/agent",
			HubAPIURL:  "http://localhost",
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")
	enrollmentTokenFile := filepath.Join(tmpDir, "enrollment-token")
	if err := os.WriteFile(enrollmentTokenFile, []byte("test-enroll-token\n"), 0o600); err != nil {
		t.Fatalf("write enrollment token file: %v", err)
	}

	cfg := &RuntimeConfig{
		AssetID:                 "configured-enrollment-node",
		EnrollmentToken:         "test-enroll-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		APIBaseURL:              server.URL,
		TokenFilePath:           tokenFile,
	}

	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "new-agent-token" {
		t.Fatalf("expected 'new-agent-token', got %q", cfg.APIToken)
	}

	// Verify token was persisted
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != "new-agent-token\n" {
		t.Fatalf("expected persisted token, got %q", string(data))
	}
	if _, err := os.Stat(enrollmentTokenFile); !os.IsNotExist(err) {
		t.Fatalf("consumed enrollment token file was not removed: %v", err)
	}
	if cfg.EnrollmentToken != "" || cfg.EnrollmentTokenFromFile {
		t.Fatal("consumed enrollment token remained in runtime configuration")
	}

	// A clean process restart must recover the token-bound asset identity and
	// both hub endpoints, not fall back to a pre-enrollment display name.
	restarted := &RuntimeConfig{
		AssetID:       "stale-configured-name",
		TokenFilePath: tokenFile,
	}
	if err := ResolveToken(context.Background(), restarted); err != nil {
		t.Fatalf("restart ResolveToken returned error: %v", err)
	}
	if restarted.AssetID != cfg.AssetID {
		t.Fatalf("restart AssetID=%q, want canonical %q", restarted.AssetID, cfg.AssetID)
	}
	if restarted.WSBaseURL != "ws://localhost/ws/agent" {
		t.Fatalf("restart WSBaseURL=%q", restarted.WSBaseURL)
	}
	if restarted.APIBaseURL != "http://localhost" {
		t.Fatalf("restart APIBaseURL=%q", restarted.APIBaseURL)
	}
	stateInfo, err := os.Stat(filepath.Join(tmpDir, enrollmentStateFileName))
	if err != nil {
		t.Fatalf("stat enrollment state: %v", err)
	}
	if stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment state mode=%o, want 600", stateInfo.Mode().Perm())
	}
}

func TestSelectEnrollmentHostname(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		system     string
		want       string
	}{
		{
			name:       "valid configured asset ID wins",
			configured: " custom-node_1 ",
			system:     "system-node",
			want:       "custom-node_1",
		},
		{
			name:       "invalid configured asset ID falls back to system hostname",
			configured: "custom node",
			system:     "system-node",
			want:       "system-node",
		},
		{
			name:       "empty configured asset ID uses system hostname",
			configured: "",
			system:     "system-node",
			want:       "system-node",
		},
		{
			name:       "invalid system hostname uses safe default",
			configured: "custom node",
			system:     "unsafe\nhost",
			want:       "labtether-agent",
		},
		{
			name:       "empty identities use safe default",
			configured: "",
			system:     "",
			want:       "labtether-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectEnrollmentHostname(tt.configured, tt.system); got != tt.want {
				t.Fatalf("selectEnrollmentHostname(%q, %q)=%q, want %q", tt.configured, tt.system, got, tt.want)
			}
		})
	}
}

func TestResolveTokenPersistenceFailureIsVisibleAndConsumesRecoverySource(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "memory-only-agent-token",
			AssetID:    "persistence-failure-node",
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	blockingParent := filepath.Join(tmpDir, "not-a-directory")
	if err := os.WriteFile(blockingParent, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(blockingParent, "agent-token")
	enrollmentTokenFile := filepath.Join(tmpDir, "enrollment-token")
	if err := os.WriteFile(enrollmentTokenFile, []byte("one-time-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &RuntimeConfig{
		EnrollmentToken:         "one-time-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		APIBaseURL:              server.URL,
		TokenFilePath:           tokenFile,
	}
	err := ResolveToken(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "persist issued agent token") {
		t.Fatalf("expected visible token persistence failure, got %v", err)
	}
	if !errors.Is(err, errAgentTokenPersistence) {
		t.Fatalf("persistence failure lost typed classification: %v", err)
	}
	if cfg.APIToken != "memory-only-agent-token" {
		t.Fatalf("in-memory replacement token=%q", cfg.APIToken)
	}
	if _, statErr := os.Stat(tokenFile); statErr == nil {
		t.Fatalf("stale token target remained after persistence failure: %v", statErr)
	}
	if _, statErr := os.Stat(enrollmentTokenFile); !os.IsNotExist(statErr) {
		t.Fatalf("consumed enrollment token file remained: %v", statErr)
	}
	if cfg.EnrollmentToken != "" || cfg.EnrollmentTokenFromFile {
		t.Fatal("consumed enrollment token remained armed in memory")
	}
}

func TestEnrollWithHubWithIdentitySendsTokenBoundProof(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode enrollment request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.DeviceKeyAlg != agentidentity.KeyAlgorithmEd25519 ||
			request.DevicePublicKey != identity.PublicKeyBase64 ||
			request.DeviceFingerprint != identity.Fingerprint {
			t.Error("enrollment request is missing device continuity fields")
		}
		signature, err := base64.StdEncoding.DecodeString(request.DeviceSignature)
		if err != nil {
			t.Errorf("decode device signature: %v", err)
		}
		payload := agentidentity.BuildTokenEnrollmentProofPayload(request.Hostname, request.EnrollmentToken, identity.Fingerprint)
		if !ed25519.Verify(publicKey, payload, signature) {
			t.Error("device continuity signature did not verify")
		}
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "identity-agent-token",
			AssetID:    "identity-node",
		})
	}))
	defer server.Close()

	cfg := &RuntimeConfig{
		EnrollmentToken: "identity-enrollment-token",
		APIBaseURL:      server.URL,
	}
	response, err := enrollWithHubWithIdentity(context.Background(), cfg, identity)
	if err != nil {
		t.Fatalf("enroll with identity: %v", err)
	}
	if response.AgentToken != "identity-agent-token" {
		t.Fatalf("agent token=%q", response.AgentToken)
	}
}

func TestResolveToken_NoAuth(t *testing.T) {
	cfg := &RuntimeConfig{}
	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "" {
		t.Fatalf("expected empty token for legacy mode, got %q", cfg.APIToken)
	}
}

func TestResolveToken_EnrollmentMissingURL(t *testing.T) {
	cfg := &RuntimeConfig{
		EnrollmentToken: "some-token",
		// No WSBaseURL or APIBaseURL
	}
	err := ResolveToken(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error when enrollment token set but no URL")
	}
}

func TestResolveToken_Priority_ExplicitOverFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")
	os.WriteFile(tokenFile, []byte("file-token\n"), 0600)

	cfg := &RuntimeConfig{
		APIToken:      "explicit-token",
		TokenFilePath: tokenFile,
	}
	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "explicit-token" {
		t.Fatalf("expected explicit token to take priority, got %q", cfg.APIToken)
	}
}

func TestEnrollWithHub_BadStatus(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := &RuntimeConfig{
		EnrollmentToken: "bad-token",
		APIBaseURL:      server.URL,
	}

	_, err := enrollWithHub(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error for 401 response")
	}
	if !isEnrollmentCredentialRejected(err) {
		t.Fatalf("expected rejected credential classification, got %v", err)
	}
}

func TestEnrollmentCredentialRejectionExcludesTransientStatus(t *testing.T) {
	if isEnrollmentCredentialRejected(&enrollmentHTTPStatusError{statusCode: http.StatusServiceUnavailable}) {
		t.Fatal("transient server status was classified as a credential rejection")
	}
	if !isEnrollmentCredentialRejected(fmt.Errorf("wrapped: %w", &enrollmentHTTPStatusError{statusCode: http.StatusForbidden})) {
		t.Fatal("wrapped forbidden response was not classified as a credential rejection")
	}
}

func TestEnrollWithHub_WSURLConversion(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "ws-token",
			AssetID:    "ws-node",
			HubWSURL:   "ws://localhost/ws/agent",
			HubAPIURL:  "http://localhost",
		})
	}))
	defer server.Close()

	// Convert http://host:port to ws://host:port/ws/agent
	wsURL := "ws" + server.URL[4:] + "/ws/agent"

	cfg := &RuntimeConfig{
		EnrollmentToken: "test-token",
		WSBaseURL:       wsURL,
	}

	resp, err := enrollWithHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AgentToken != "ws-token" {
		t.Fatalf("expected 'ws-token', got %q", resp.AgentToken)
	}
}

func TestEnrollmentResponseIsBoundedAndSingleDocument(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "oversized",
			body: `{"agent_token":"` + strings.Repeat("x", maxEnrollmentResponseBytes) + `"}`,
			want: "exceeds",
		},
		{
			name: "trailing document",
			body: `{"agent_token":"token","asset_id":"node"}{}`,
			want: "trailing data",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			cfg := &RuntimeConfig{
				EnrollmentToken: "one-time",
				APIBaseURL:      server.URL,
				TokenFilePath:   filepath.Join(t.TempDir(), "agent-token"),
			}
			err := ResolveToken(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ResolveToken error=%v, want %q", err, test.want)
			}
		})
	}
}
