//go:build !windows

package agentcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// The container image mounts the enrollment token read-only. Enrollment must
// succeed even though the consumed file cannot be deleted, and later starts
// must never offer that consumed token to the Hub again.
func TestReadOnlyEnrollmentTokenIsUsedOnceAndThenIgnored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permission")
	}
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	var enrollCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrollCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "issued-agent-token",
			AssetID:    "readonly-secret-node",
			HubWSURL:   "ws://localhost/ws/agent",
			HubAPIURL:  "http://localhost",
		})
	}))
	defer server.Close()

	stateDir := t.TempDir()
	tokenFile := filepath.Join(stateDir, "agent-token")
	secretDir := t.TempDir()
	enrollmentTokenFile := filepath.Join(secretDir, "enrollment-token")
	if err := os.WriteFile(enrollmentTokenFile, []byte("one-time-token\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secretDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secretDir, 0o700) })

	first := &RuntimeConfig{
		AssetID:                 "readonly-secret-node",
		EnrollmentToken:         "one-time-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		APIBaseURL:              server.URL,
		TokenFilePath:           tokenFile,
	}
	if err := ResolveToken(context.Background(), first); err != nil {
		t.Fatalf("enrollment with a read-only token file failed: %v", err)
	}
	if first.APIToken != "issued-agent-token" || first.EnrollmentToken != "" {
		t.Fatalf("token=%q enrollment armed=%q", first.APIToken, first.EnrollmentToken)
	}
	if _, err := os.Stat(enrollmentTokenFile); err != nil {
		t.Fatalf("read-only token file should remain in place: %v", err)
	}

	restarted := &RuntimeConfig{
		EnrollmentToken:         "one-time-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		APIBaseURL:              server.URL,
		TokenFilePath:           tokenFile,
	}
	if err := ResolveToken(context.Background(), restarted); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if restarted.APIToken != "issued-agent-token" {
		t.Fatalf("restart did not load the saved agent token: %q", restarted.APIToken)
	}
	if restarted.EnrollmentToken != "" || restarted.EnrollmentTokenFromFile {
		t.Fatal("consumed read-only enrollment token was armed for re-enrollment")
	}
	if got := enrollCalls.Load(); got != 1 {
		t.Fatalf("Hub saw %d enrollment requests, want 1", got)
	}

	staged := &RuntimeConfig{
		EnrollmentToken:         "fresh-recovery-token",
		EnrollmentTokenFilePath: enrollmentTokenFile,
		EnrollmentTokenFromFile: true,
		TokenFilePath:           tokenFile,
	}
	if err := ResolveToken(context.Background(), staged); err != nil {
		t.Fatalf("staged token: %v", err)
	}
	if staged.EnrollmentToken != "fresh-recovery-token" {
		t.Fatal("a newly staged enrollment token must stay available for recovery")
	}
}
