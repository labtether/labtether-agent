package agentcore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

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
	if cfg.APIBaseURL != "https://operator-override.example.test:9443" {
		t.Fatalf("APIBaseURL=%q, want API origin derived from explicit WS endpoint", cfg.APIBaseURL)
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
