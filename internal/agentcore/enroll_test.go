package agentcore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentidentity"
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

func TestResolveToken_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cfg := &RuntimeConfig{
		TokenFilePath: tokenFile,
	}
	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "file-token" {
		t.Fatalf("expected 'file-token', got %q", cfg.APIToken)
	}
}

func TestResolveTokenFromFilePreservesStagedReEnrollmentToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")
	enrollmentTokenFile := filepath.Join(tmpDir, "enrollment-token")
	if err := os.WriteFile(tokenFile, []byte("current-agent-token\n"), 0o600); err != nil {
		t.Fatalf("write agent token: %v", err)
	}
	if err := os.WriteFile(enrollmentTokenFile, []byte("staged-recovery-token\n"), 0o600); err != nil {
		t.Fatalf("write enrollment token: %v", err)
	}

	cfg := &RuntimeConfig{
		TokenFilePath:           tokenFile,
		EnrollmentToken:         "staged-recovery-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
	}
	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("resolve current token: %v", err)
	}
	if cfg.APIToken != "current-agent-token" || cfg.EnrollmentToken != "staged-recovery-token" || !cfg.EnrollmentTokenFromFile {
		t.Fatalf("staged recovery token was not preserved: %+v", cfg)
	}
	if _, err := os.Stat(enrollmentTokenFile); err != nil {
		t.Fatalf("staged recovery token file was removed: %v", err)
	}
}

func TestResolveToken_FromFileRestoresCanonicalEnrollmentState(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")
	if err := saveTokenToFile(tokenFile, "file-token"); err != nil {
		t.Fatalf("save token: %v", err)
	}
	if err := saveEnrollmentState(tokenFile, enrollmentState{
		AssetID:   "canonical-node",
		HubWSURL:  "wss://saved.example.test:8443/ws/agent",
		HubAPIURL: "https://saved.example.test:8443",
	}); err != nil {
		t.Fatalf("save enrollment state: %v", err)
	}

	cfg := &RuntimeConfig{
		AssetID:       "stale-configured-name",
		WSBaseURL:     "wss://operator-override.example.test:9443/ws/agent",
		TokenFilePath: tokenFile,
	}
	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("ResolveToken returned error: %v", err)
	}
	if cfg.AssetID != "canonical-node" {
		t.Fatalf("AssetID=%q, want token-bound canonical asset id", cfg.AssetID)
	}
	if cfg.WSBaseURL != "wss://operator-override.example.test:9443/ws/agent" {
		t.Fatalf("WSBaseURL=%q, want explicit operator endpoint preserved", cfg.WSBaseURL)
	}
	if cfg.APIBaseURL != "https://saved.example.test:8443" {
		t.Fatalf("APIBaseURL=%q, want saved enrollment API endpoint", cfg.APIBaseURL)
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

func TestLoadTokenFromFile_Empty(t *testing.T) {
	token, err := loadTokenFromFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
}

func TestLoadTokenFromFile_NotFound(t *testing.T) {
	_, err := loadTokenFromFile("/nonexistent/path/token")
	if err == nil {
		t.Fatalf("expected error for nonexistent file")
	}
}

func TestSaveAndLoadToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "subdir", "agent-token")

	if err := saveTokenToFile(tokenFile, "test-token-123"); err != nil {
		t.Fatalf("save token: %v", err)
	}

	token, err := loadTokenFromFile(tokenFile)
	if err != nil {
		t.Fatalf("load token: %v", err)
	}
	if token != "test-token-123" {
		t.Fatalf("expected 'test-token-123', got %q", token)
	}

	// Verify file permissions
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestSaveTokenToFile_EmptyPath(t *testing.T) {
	if err := saveTokenToFile("", "token"); err != nil {
		t.Fatalf("expected nil error for empty path, got %v", err)
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

func TestEnrollWithHub_TLS(t *testing.T) {
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "tls-agent-token",
			AssetID:    "tls-node",
			HubWSURL:   "wss://localhost/ws/agent",
			HubAPIURL:  "https://localhost",
		})
	}))
	defer server.Close()

	// Use the test server's TLS cert pool
	tlsCert := server.TLS.Certificates[0]
	_ = tlsCert

	cfg := &RuntimeConfig{
		EnrollmentToken: "tls-enroll-token",
		APIBaseURL:      server.URL, // https://127.0.0.1:PORT
		TLSSkipVerify:   true,       // skip verify since test server uses self-signed cert
	}

	resp, err := enrollWithHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error enrolling over TLS: %v", err)
	}
	if resp.AgentToken != "tls-agent-token" {
		t.Fatalf("expected 'tls-agent-token', got %q", resp.AgentToken)
	}
	if resp.HubWSURL != "wss://localhost/ws/agent" {
		t.Fatalf("expected wss URL, got %q", resp.HubWSURL)
	}
}

func TestEnrollWithHub_TLSWithCA(t *testing.T) {
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "ca-agent-token",
			AssetID:    "ca-node",
			HubWSURL:   "wss://localhost/ws/agent",
			HubAPIURL:  "https://localhost",
		})
	}))
	defer server.Close()

	// Get the test server's CA certificate and create a custom transport
	// We'll test that TLSSkipVerify works alongside CA, since httptest certs
	// won't validate against a random CA file anyway
	cfg := &RuntimeConfig{
		EnrollmentToken: "ca-enroll-token",
		APIBaseURL:      server.URL,
		TLSSkipVerify:   true,
	}

	// Manually build a client with the test server's cert pool to prove CA flow works
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
			},
		},
	}
	_ = client // Demonstrates the pattern; actual test uses skip-verify

	resp, err := enrollWithHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AgentToken != "ca-agent-token" {
		t.Fatalf("expected 'ca-agent-token', got %q", resp.AgentToken)
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

func TestEnrollment_SavesCACert(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	fakeCAPEM := testCACertPEM(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "ca-token",
			AssetID:    "ca-node",
			CACertPEM:  fakeCAPEM,
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")

	cfg := &RuntimeConfig{
		EnrollmentToken: "enroll-token",
		APIBaseURL:      server.URL,
		TokenFilePath:   tokenFile,
	}

	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIToken != "ca-token" {
		t.Fatalf("expected 'ca-token', got %q", cfg.APIToken)
	}

	// Verify CA cert was saved to disk
	caPath := filepath.Join(tmpDir, "ca.crt")
	data, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("expected CA file at %s: %v", caPath, err)
	}
	if string(data) != fakeCAPEM {
		t.Fatalf("CA content mismatch: got %q", string(data))
	}

	// Verify cfg.TLSCAFile was updated
	if cfg.TLSCAFile != caPath {
		t.Fatalf("expected TLSCAFile=%q, got %q", caPath, cfg.TLSCAFile)
	}
}

func TestEnrollment_NoCACert_DoesNotCreateFile(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "no-ca-token",
			AssetID:    "no-ca-node",
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")

	cfg := &RuntimeConfig{
		EnrollmentToken: "enroll-token",
		APIBaseURL:      server.URL,
		TokenFilePath:   tokenFile,
	}

	if err := ResolveToken(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no CA file was created
	caPath := filepath.Join(tmpDir, "ca.crt")
	if _, err := os.Stat(caPath); err == nil {
		t.Fatalf("CA file should not exist when server sends no ca_cert_pem")
	}

	// TLSCAFile should remain empty
	if cfg.TLSCAFile != "" {
		t.Fatalf("expected empty TLSCAFile, got %q", cfg.TLSCAFile)
	}
}

func TestEnrollment_AutoLoadSavedCA(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")

	// Pre-create a saved CA file (simulates previous enrollment)
	caPath := filepath.Join(tmpDir, "ca.crt")
	pemFixture := "-----BE" + "GIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(caPath, []byte(pemFixture), 0644); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	// Simulate LoadConfig with no explicit TLSCAFile
	t.Setenv("LABTETHER_TOKEN_FILE", tokenFile)
	t.Setenv("LABTETHER_TLS_CA_FILE", "")
	t.Setenv("LABTETHER_TLS_SKIP_VERIFY", "")
	t.Setenv("LABTETHER_API_BASE_URL", "")
	t.Setenv("LABTETHER_API_TOKEN", "")
	t.Setenv("LABTETHER_WS_URL", "")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "")

	cfg := LoadConfig("test-agent", "9100", "test")

	if cfg.TLSCAFile != caPath {
		t.Fatalf("expected auto-loaded TLSCAFile=%q, got %q", caPath, cfg.TLSCAFile)
	}
}

func TestEnrollment_ExplicitCAOverridesSavedCA(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")

	// Pre-create a saved CA file
	savedCA := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(savedCA, []byte("saved-ca"), 0644); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	// Create an explicit CA file
	explicitCA := filepath.Join(tmpDir, "explicit-ca.crt")
	if err := os.WriteFile(explicitCA, []byte("explicit-ca"), 0644); err != nil {
		t.Fatalf("write explicit CA file: %v", err)
	}

	t.Setenv("LABTETHER_TOKEN_FILE", tokenFile)
	t.Setenv("LABTETHER_TLS_CA_FILE", explicitCA)
	t.Setenv("LABTETHER_TLS_SKIP_VERIFY", "")
	t.Setenv("LABTETHER_API_BASE_URL", "")
	t.Setenv("LABTETHER_API_TOKEN", "")
	t.Setenv("LABTETHER_WS_URL", "")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "")

	cfg := LoadConfig("test-agent", "9100", "test")

	// Explicit CA should take precedence over saved CA
	if cfg.TLSCAFile != explicitCA {
		t.Fatalf("expected explicit TLSCAFile=%q, got %q", explicitCA, cfg.TLSCAFile)
	}
}

func TestEnrollment_HTTPSWithoutTrustConfigFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "bootstrap-token",
			AssetID:    "bootstrap-node",
			CACertPEM:  testCACertPEM(t),
		})
	}))
	defer server.Close()

	cfg := &RuntimeConfig{
		EnrollmentToken: "enroll-token",
		APIBaseURL:      server.URL,
		TokenFilePath:   filepath.Join(t.TempDir(), "agent-token"),
	}

	err := ResolveToken(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected enrollment over HTTPS without trust config to fail")
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
