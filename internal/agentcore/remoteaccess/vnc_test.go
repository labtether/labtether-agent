package remoteaccess

import (
	"fmt"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildX11VNCArgsDefaults(t *testing.T) {
	args := BuildX11VNCArgs("", 5901, "", "", "")

	requireArgPair(t, args, "-display", ":0")
	requireArgPair(t, args, "-rfbport", "5901")
	requireArgPair(t, args, "-auth", "guess")
	requireArgPair(t, args, "-speeds", "dsl")

	requireNoStandaloneArg(t, args, "-quality")
	requireNoStandaloneArg(t, args, "-compress")
	requireNoStandaloneArg(t, args, "-rfbauth")
}

func TestBuildX11VNCArgsQualityMapping(t *testing.T) {
	tests := []struct {
		name    string
		quality string
		speeds  string
	}{
		{name: "low", quality: "low", speeds: "modem"},
		{name: "medium", quality: "medium", speeds: "dsl"},
		{name: "high", quality: "high", speeds: "lan"},
		{name: "unknown-default", quality: "custom", speeds: "dsl"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := BuildX11VNCArgs(":2", 5909, tc.quality, "", "")
			requireArgPair(t, args, "-display", ":2")
			requireArgPair(t, args, "-rfbport", "5909")
			requireArgPair(t, args, "-speeds", tc.speeds)
		})
	}
}

func TestBuildX11VNCArgsUsesAuthFileWhenPresent(t *testing.T) {
	authPath := "/tmp/labtether-x11vnc-auth.rfbauth"
	args := BuildX11VNCArgs(":1", 5902, "medium", authPath, "")

	requireArgPair(t, args, "-rfbauth", authPath)
	requireNoStandaloneArg(t, args, "-nopw")
}

func TestBuildX11VNCArgsUsesXauthPathWhenPresent(t *testing.T) {
	xauthPath := "/tmp/labtether-xauth-99-abc.xauth"
	args := BuildX11VNCArgs(":99", 5903, "", "", xauthPath)

	requireArgPair(t, args, "-auth", xauthPath)
}

func TestBuildX11VNCArgsFallsBackToGuessWithoutXauth(t *testing.T) {
	args := BuildX11VNCArgs(":0", 5901, "", "", "")
	requireArgPair(t, args, "-auth", "guess")
}

func TestBuildX11VNCArgsOmitsAuthWhenNone(t *testing.T) {
	args := BuildX11VNCArgs(":99", 5901, "", "", "none")
	requireNoStandaloneArg(t, args, "-auth")
}

func TestBuildX11ClientEnvIncludesDisplayAndXauthority(t *testing.T) {
	originalDiscover := DiscoverDisplayXAuthorityFn
	t.Cleanup(func() {
		DiscoverDisplayXAuthorityFn = originalDiscover
	})
	DiscoverDisplayXAuthorityFn = func(string) string { return "" }

	t.Setenv("DISPLAY", ":0")
	t.Setenv("XAUTHORITY", "/tmp/original.xauth")

	env := BuildX11ClientEnv(":99", "/tmp/labtether-99.xauth")
	if !ContainsEnvValue(env, "DISPLAY=:99") {
		t.Fatalf("expected DISPLAY override, got %v", env)
	}
	if !ContainsEnvValue(env, "XAUTHORITY=/tmp/labtether-99.xauth") {
		t.Fatalf("expected XAUTHORITY override, got %v", env)
	}
	if ContainsEnvValue(env, "XAUTHORITY=/tmp/original.xauth") {
		t.Fatalf("expected stale XAUTHORITY to be removed, got %v", env)
	}
}

func TestBuildX11ClientEnvOmitsXauthorityWhenUnavailable(t *testing.T) {
	originalDiscover := DiscoverDisplayXAuthorityFn
	t.Cleanup(func() {
		DiscoverDisplayXAuthorityFn = originalDiscover
	})
	DiscoverDisplayXAuthorityFn = func(string) string { return "" }

	t.Setenv("DISPLAY", ":0")
	t.Setenv("XAUTHORITY", "/tmp/original.xauth")

	for _, xauthPath := range []string{"", "none"} {
		env := BuildX11ClientEnv(":98", xauthPath)
		if !ContainsEnvValue(env, "DISPLAY=:98") {
			t.Fatalf("expected DISPLAY override for %q, got %v", xauthPath, env)
		}
		for _, entry := range env {
			if strings.HasPrefix(entry, "XAUTHORITY=") {
				t.Fatalf("expected no XAUTHORITY for %q, got %v", xauthPath, env)
			}
		}
	}
}

func TestBuildX11ClientEnvDiscoversRealDisplayXauthority(t *testing.T) {
	originalDiscover := DiscoverDisplayXAuthorityFn
	t.Cleanup(func() {
		DiscoverDisplayXAuthorityFn = originalDiscover
	})
	DiscoverDisplayXAuthorityFn = func(display string) string {
		if display != ":0" {
			t.Fatalf("display=%q, want :0", display)
		}
		return "/run/lightdm/root/:0"
	}

	env := BuildX11ClientEnv(":0", "")
	if !ContainsEnvValue(env, "DISPLAY=:0") {
		t.Fatalf("expected DISPLAY override, got %v", env)
	}
	if !ContainsEnvValue(env, "XAUTHORITY=/run/lightdm/root/:0") {
		t.Fatalf("expected discovered XAUTHORITY, got %v", env)
	}
}

func TestBuildXvfbArgs(t *testing.T) {
	args := BuildXvfbArgs(99, 1920, 1080)
	expected := []string{":99", "-screen", "0", "1920x1080x24"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("BuildXvfbArgs: got %v, want %v", args, expected)
	}
}

func TestIsDisplayError(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"cannot open display :0", true},
		{"unable to connect to X server", true},
		{"XOpenDisplay failed", true},
		{"no DISPLAY set", true},
		{"DISPLAY variable not set", true},
		{"VNC server not ready: timeout waiting for VNC on port 5901", false},
		{"failed to start x11vnc: exit status 1", false},
	}
	for _, tt := range tests {
		got := IsDisplayError(fmt.Errorf("%s", tt.msg))
		if got != tt.want {
			t.Errorf("IsDisplayError(%q) = %v, want %v", tt.msg, got, tt.want)
		}
	}
}

func TestSummarizeProcessLogTail(t *testing.T) {
	logTail := "\nline-1\nline-2\nline-3\nline-4\n"
	summary := SummarizeProcessLogTail(logTail)
	if summary == "" {
		t.Fatalf("expected non-empty summary")
	}
	if summary != "x11vnc log tail: line-2 | line-3 | line-4" {
		t.Fatalf("unexpected summary: %q", summary)
	}
}

func TestStartDesktopBootstrapShellRequiresXterm(t *testing.T) {
	originalPath := t.TempDir()
	t.Setenv("PATH", originalPath)

	_, err := StartDesktopBootstrapShell(":99", "")
	if err == nil {
		t.Fatal("expected missing xterm error")
	}
	if !strings.Contains(err.Error(), "xterm not found") {
		t.Fatalf("error=%q, want xterm missing hint", err)
	}
}

func requireArgPair(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return
		}
	}
	t.Fatalf("expected args to contain pair %q %q, got %v", flag, value, args)
}

func requireNoStandaloneArg(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, arg := range args {
		if arg == flag {
			t.Fatalf("expected args to not contain %q, got %v", flag, args)
		}
	}
}

// ContainsEnvValue moved to test_helpers_test.go

func TestWaitForXvfbReadySucceedsWhenLockFileExists(t *testing.T) {
	display := 88
	lockFile := fmt.Sprintf("/tmp/.X%d-lock", display)
	if err := os.WriteFile(lockFile, []byte("12345\n"), 0o644); err != nil {
		t.Fatalf("failed to create mock lock file: %v", err)
	}
	defer os.Remove(lockFile)
	err := WaitForXvfbReady(display, 2*time.Second)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestWaitForXvfbReadyTimesOutWhenNoLockFile(t *testing.T) {
	err := WaitForXvfbReady(87, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout in error message, got: %v", err)
	}
}

func TestGenerateHexCookie(t *testing.T) {
	cookie := GenerateHexCookie(32)
	if len(cookie) != 32 {
		t.Fatalf("expected 32-char cookie, got %d chars: %q", len(cookie), cookie)
	}
	// Verify it's valid hex.
	for _, c := range cookie {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("cookie contains non-hex char %q: %q", string(c), cookie)
		}
	}
	// Two calls should produce different values.
	cookie2 := GenerateHexCookie(32)
	if cookie == cookie2 {
		t.Fatalf("expected unique cookies, got identical: %q", cookie)
	}
}

func TestCreateXauthorityFile(t *testing.T) {
	path, err := CreateXauthorityFile(99)
	if err != nil {
		t.Skipf("xauth not available: %v", err)
	}
	defer os.Remove(path)
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("file not found: %v", statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
	}
}

func TestIsDisplayAvailableUsesLockFile(t *testing.T) {
	originalCollectUserSessions := system.CollectUserSessionsFn
	t.Cleanup(func() {
		system.CollectUserSessionsFn = originalCollectUserSessions
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }

	lockFile := "/tmp/.X86-lock"
	if err := os.WriteFile(lockFile, []byte("12345\n"), 0o644); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}
	defer os.Remove(lockFile)

	if !IsDisplayAvailable(":86") {
		t.Fatal("expected display to be available with lock file present")
	}

	if IsDisplayAvailable(":85") {
		t.Fatal("expected display without lock file or active session to be unavailable")
	}
}
