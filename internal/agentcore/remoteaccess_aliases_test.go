package agentcore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/remoteaccess"
)

func TestExecConfigRoundTripPreservesSelfUpdateContext(t *testing.T) {
	want := RuntimeConfig{
		APIBaseURL:         "https://hub.example.test",
		APIToken:           "agent-token",
		WSBaseURL:          "wss://hub.example.test/ws/agent",
		AutoUpdateCheckURL: "https://updates.example.test/latest",
		TLSCAFile:          "/etc/labtether/ca.pem",
		TLSSkipVerify:      true,
		Version:            "v1.6.5",
	}

	got := runtimeConfigFromExecConfig(execConfigFromRuntimeConfig(want))
	if got.APIBaseURL != want.APIBaseURL || got.APIToken != want.APIToken ||
		got.WSBaseURL != want.WSBaseURL || got.AutoUpdateCheckURL != want.AutoUpdateCheckURL ||
		got.TLSCAFile != want.TLSCAFile || got.TLSSkipVerify != want.TLSSkipVerify ||
		got.Version != want.Version {
		t.Fatalf("self-update config round trip lost fields: got=%+v want=%+v", got, want)
	}
}

func TestRemoteSelfUpdateReportsMissingEndpointAsFailure(t *testing.T) {
	t.Setenv(envNativeWrapperParentPID, "")
	updated, summary, err := remoteaccess.SelfUpdateFn(remoteaccess.ExecConfig{APIToken: "opaque-agent-token"}, false)
	if err == nil {
		t.Fatal("expected missing self-update endpoint to fail")
	}
	if updated || summary != "" {
		t.Fatalf("missing endpoint result = updated %v summary %q, want false and empty", updated, summary)
	}
}

func TestRemoteSelfUpdateUsesPreservedEndpointAndVersion(t *testing.T) {
	t.Setenv(envNativeWrapperParentPID, "")
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")
	tempDir := t.TempDir()
	executablePath := filepath.Join(tempDir, "labtether-agent")
	currentBinary := []byte("current-binary")
	if err := os.WriteFile(executablePath, currentBinary, 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	originalExecutablePathFn := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = originalExecutablePathFn })

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/v1/agent/releases/latest") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(agentReleaseMetadata{
			Version: "v2.0.0",
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			SHA256:  sha256Hex(currentBinary),
			URL:     server.URL + "/binary",
		})
	}))
	defer server.Close()

	updated, summary, err := remoteaccess.SelfUpdateFn(execConfigFromRuntimeConfig(RuntimeConfig{
		APIBaseURL: server.URL,
		APIToken:   "opaque-agent-token",
		Version:    "v1.9.0",
	}), false)
	if err != nil {
		t.Fatalf("remote self-update failed: %v", err)
	}
	if updated || !strings.Contains(summary, "up to date") {
		t.Fatalf("remote self-update = updated %v summary %q", updated, summary)
	}
}
