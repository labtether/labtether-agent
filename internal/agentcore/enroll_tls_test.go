package agentcore

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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

func TestEnrollWithHub_TLSWithCAOverridesSkipVerify(t *testing.T) {
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

	caPath := filepath.Join(t.TempDir(), "hub-ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &RuntimeConfig{
		EnrollmentToken: "ca-enroll-token",
		APIBaseURL:      server.URL,
		TLSCAFile:       caPath,
		TLSSkipVerify:   true,
	}
	resp, err := enrollWithHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AgentToken != "ca-agent-token" {
		t.Fatalf("expected 'ca-agent-token', got %q", resp.AgentToken)
	}
	wrongCAPath := filepath.Join(t.TempDir(), "wrong-ca.crt")
	if err := os.WriteFile(wrongCAPath, generateTestCACert(t), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.TLSCAFile = wrongCAPath
	if _, err := enrollWithHub(context.Background(), cfg); err == nil {
		t.Fatal("untrusted Hub certificate was accepted while CA and skip-verify were both set")
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
