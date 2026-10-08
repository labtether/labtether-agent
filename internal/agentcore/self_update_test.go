package agentcore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestBuildAgentReleaseCheckURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  RuntimeConfig
		want string
	}{
		{
			name: "custom override",
			cfg: RuntimeConfig{
				AutoUpdateCheckURL: "https://updates.example.com/release",
			},
			want: "https://updates.example.com/release",
		},
		{
			name: "api base",
			cfg: RuntimeConfig{
				APIBaseURL: "https://hub.example.com",
			},
			want: "https://hub.example.com/api/v1/agent/releases/latest",
		},
		{
			name: "ws base with path",
			cfg: RuntimeConfig{
				WSBaseURL: "wss://hub.example.com/ws/agent",
			},
			want: "https://hub.example.com/api/v1/agent/releases/latest",
		},
		{
			name: "missing base urls",
			cfg:  RuntimeConfig{},
			want: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := buildAgentReleaseCheckURL(tc.cfg); got != tc.want {
				t.Fatalf("buildAgentReleaseCheckURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckAndApplySelfUpdate_ReplacesExecutable(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")
	tempDir := t.TempDir()
	executablePath := filepath.Join(tempDir, "labtether-agent")
	if err := os.WriteFile(executablePath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write old executable: %v", err)
	}

	newBinary := []byte("new-binary-content")
	newSHA := sha256Hex(newBinary)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": "v2.0.0",
				"os":      runtime.GOOS,
				"arch":    runtime.GOARCH,
				"sha256":  newSHA,
				"url":     server.URL + "/binary",
			})
		case "/binary":
			_, _ = w.Write(newBinary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalExecutablePathFn := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = originalExecutablePathFn })

	updated, summary, err := checkAndApplySelfUpdate(RuntimeConfig{
		AutoUpdateEnabled:  true,
		AutoUpdateCheckURL: server.URL + "/release",
	})
	if err != nil {
		t.Fatalf("checkAndApplySelfUpdate returned error: %v", err)
	}
	if !updated {
		t.Fatalf("expected update to be applied")
	}
	if !strings.Contains(summary, "v2.0.0") {
		t.Fatalf("expected summary to mention release version, got %q", summary)
	}

	content, err := os.ReadFile(executablePath)
	if err != nil {
		t.Fatalf("read replaced executable: %v", err)
	}
	if string(content) != string(newBinary) {
		t.Fatalf("unexpected executable contents after update: got %q", string(content))
	}
}

func TestCheckAndApplySelfUpdate_NoopWhenChecksumMatches(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")
	tempDir := t.TempDir()
	executablePath := filepath.Join(tempDir, "labtether-agent")
	currentBinary := []byte("same-binary-content")
	if err := os.WriteFile(executablePath, currentBinary, 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}

	currentSHA := sha256Hex(currentBinary)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/release" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": "v2.0.0",
				"os":      runtime.GOOS,
				"arch":    runtime.GOARCH,
				"sha256":  currentSHA,
				"url":     server.URL + "/binary",
			})
			return
		}
		_, _ = w.Write(currentBinary)
	}))
	defer server.Close()

	originalExecutablePathFn := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = originalExecutablePathFn })

	updated, summary, err := checkAndApplySelfUpdate(RuntimeConfig{
		AutoUpdateEnabled:  true,
		AutoUpdateCheckURL: server.URL + "/release",
	})
	if err != nil {
		t.Fatalf("checkAndApplySelfUpdate returned error: %v", err)
	}
	if updated {
		t.Fatalf("expected no update when checksums match")
	}
	if !strings.Contains(summary, "up to date") {
		t.Fatalf("expected up-to-date summary, got %q", summary)
	}
}

func TestCheckAndApplySelfUpdate_ForceWhenChecksumMatches(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")
	tempDir := t.TempDir()
	executablePath := filepath.Join(tempDir, "labtether-agent")
	currentBinary := []byte("same-binary-content")
	if err := os.WriteFile(executablePath, currentBinary, 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}

	currentSHA := sha256Hex(currentBinary)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/release" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": "v2.0.0",
				"os":      runtime.GOOS,
				"arch":    runtime.GOARCH,
				"sha256":  currentSHA,
				"url":     server.URL + "/binary",
			})
			return
		}
		_, _ = w.Write(currentBinary)
	}))
	defer server.Close()

	originalExecutablePathFn := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = originalExecutablePathFn })

	updated, summary, err := checkAndApplySelfUpdateWithOptions(RuntimeConfig{
		AutoUpdateEnabled:  true,
		AutoUpdateCheckURL: server.URL + "/release",
	}, selfUpdateOptions{Force: true})
	if err != nil {
		t.Fatalf("checkAndApplySelfUpdateWithOptions returned error: %v", err)
	}
	if !updated {
		t.Fatalf("expected forced update to be applied")
	}
	if !strings.Contains(summary, "forced update applied") {
		t.Fatalf("expected forced-update summary, got %q", summary)
	}
}

func TestCheckAndApplySelfUpdate_RefusesNativeWrapperManagedChild(t *testing.T) {
	t.Setenv(envNativeWrapperParentPID, "1234")
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")

	tempDir := t.TempDir()
	executablePath := filepath.Join(tempDir, "labtether-agent")
	originalBinary := []byte("signed-wrapper-child")
	if err := os.WriteFile(executablePath, originalBinary, 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer server.Close()

	originalExecutablePathFn := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = originalExecutablePathFn })

	updated, summary, err := checkAndApplySelfUpdateWithOptions(RuntimeConfig{
		AutoUpdateEnabled:  true,
		AutoUpdateCheckURL: server.URL,
	}, selfUpdateOptions{Force: true})
	if err != nil {
		t.Fatalf("checkAndApplySelfUpdateWithOptions returned error: %v", err)
	}
	if updated {
		t.Fatal("native-wrapper-managed child unexpectedly updated itself")
	}
	if summary != nativeWrapperSelfUpdateMessage {
		t.Fatalf("summary = %q, want %q", summary, nativeWrapperSelfUpdateMessage)
	}
	if requestCount != 0 {
		t.Fatalf("native-wrapper-managed child made %d update requests", requestCount)
	}
	content, err := os.ReadFile(executablePath)
	if err != nil {
		t.Fatalf("read executable: %v", err)
	}
	if string(content) != string(originalBinary) {
		t.Fatalf("native-wrapper-managed executable changed: got %q", content)
	}
}

func TestNativeWrapperSelfUpdateBlocked(t *testing.T) {
	t.Setenv(envNativeWrapperParentPID, "")

	tests := []struct {
		name           string
		executablePath string
		goos           string
		want           bool
	}{
		{
			name:           "mac app resources child",
			executablePath: "/Applications/LabTether Agent.app/Contents/Resources/labtether-agent",
			goos:           "darwin",
			want:           true,
		},
		{
			name:           "mac app executable child",
			executablePath: "/Applications/LabTether Agent.app/Contents/MacOS/labtether-agent",
			goos:           "DARWIN",
			want:           true,
		},
		{
			name:           "standalone mac agent",
			executablePath: "/usr/local/bin/labtether-agent",
			goos:           "darwin",
			want:           false,
		},
		{
			name:           "same path on linux remains standalone",
			executablePath: "/opt/LabTether Agent.app/Contents/Resources/labtether-agent",
			goos:           "linux",
			want:           false,
		},
		{
			name:           "non app suffix is not a bundle",
			executablePath: "/Applications/LabTether Agent.application/Contents/Resources/labtether-agent",
			goos:           "darwin",
			want:           false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeWrapperSelfUpdateBlocked(test.executablePath, test.goos); got != test.want {
				t.Fatalf("nativeWrapperSelfUpdateBlocked(%q, %q) = %v, want %v", test.executablePath, test.goos, got, test.want)
			}
		})
	}
}

func TestMaybeAutoUpdateOnStartupRequestsRestart(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")

	tempDir := t.TempDir()
	executablePath := filepath.Join(tempDir, "labtether-agent")
	if err := os.WriteFile(executablePath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write old executable: %v", err)
	}

	newBinary := []byte("new-binary-content")
	newSHA := sha256Hex(newBinary)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": "v2.0.0",
				"os":      runtime.GOOS,
				"arch":    runtime.GOARCH,
				"sha256":  newSHA,
				"url":     server.URL + "/binary",
			})
		case "/binary":
			_, _ = w.Write(newBinary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalExecutablePathFn := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = originalExecutablePathFn })

	var exitCode string
	originalAgentExitFn := agentExitFn
	agentExitFn = func(code int) {
		exitCode = strconv.Itoa(code)
	}
	t.Cleanup(func() { agentExitFn = originalAgentExitFn })

	err := maybeAutoUpdateOnStartup(RuntimeConfig{
		AutoUpdateEnabled:  true,
		AutoUpdateCheckURL: server.URL + "/release",
	})
	if err == nil {
		t.Fatalf("expected restart error after successful self-update")
	}
	if exitCode != strconv.Itoa(selfUpdateExitCode) {
		t.Fatalf("expected exit code %d, got %q", selfUpdateExitCode, exitCode)
	}
}
