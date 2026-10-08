package remoteaccess

import (
	"errors"
	"fmt"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestStartLinuxVNCServerRejectsWaylandRealDesktopFallback(t *testing.T) {
	originalDetectSession := DetectDesktopSessionFn
	t.Cleanup(func() {
		DetectDesktopSessionFn = originalDetectSession
	})
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Type: DesktopSessionTypeWayland, Backend: DesktopBackendWaylandPipeWire}
	}

	_, _, _, _, err := StartLinuxVNCServer("", 5901, "", "")
	if err == nil {
		t.Fatal("expected Wayland VNC start to be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported on wayland") {
		t.Fatalf("error=%q, want unsupported on wayland", err)
	}
}

func TestStartLinuxVNCServerUsesExistingDisplayWhenAvailable(t *testing.T) {
	originalLaunch := LaunchDesktopVNCReady
	originalStartXvfb := StartDesktopXvfb
	originalFind := FindDesktopFreeDisplay
	originalBootstrap := StartDesktopBootstrap
	originalCollectUserSessions := system.CollectUserSessionsFn
	originalDiscover := DiscoverDisplayXAuthorityFn
	t.Cleanup(func() {
		LaunchDesktopVNCReady = originalLaunch
		StartDesktopXvfb = originalStartXvfb
		FindDesktopFreeDisplay = originalFind
		StartDesktopBootstrap = originalBootstrap
		system.CollectUserSessionsFn = originalCollectUserSessions
		DiscoverDisplayXAuthorityFn = originalDiscover
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }
	DiscoverDisplayXAuthorityFn = func(display string) string {
		if display != ":0" {
			t.Fatalf("display=%q, want :0", display)
		}
		return "/run/lightdm/root/:0"
	}

	// Create a lock file so hasUsableDisplay(:0) returns true.
	lockFile := "/tmp/.X0-lock"
	if err := os.WriteFile(lockFile, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("failed to create mock lock file: %v", err)
	}
	defer os.Remove(lockFile)

	primaryCmd := &exec.Cmd{}
	launchCalls := 0
	LaunchDesktopVNCReady = func(display string, port int, quality, vncPassword, xauthPath string, timeout time.Duration) (*exec.Cmd, string, string, error) {
		launchCalls++
		if display != ":0" || port != 5901 || quality != "high" || vncPassword != "secret" {
			t.Fatalf("unexpected launch args display=%q port=%d quality=%q password=%q", display, port, quality, vncPassword)
		}
		if xauthPath != "/run/lightdm/root/:0" {
			t.Fatalf("xauthPath=%q, want /run/lightdm/root/:0", xauthPath)
		}
		return primaryCmd, "/tmp/auth-primary", "", nil
	}
	StartDesktopXvfb = func(int, int, int) (*exec.Cmd, string, error) {
		t.Fatal("did not expect Xvfb fallback for healthy display")
		return nil, "", nil
	}
	StartDesktopBootstrap = func(string, string) (*exec.Cmd, error) {
		t.Fatal("did not expect fallback bootstrap for healthy display")
		return nil, nil
	}

	cmd, xvfbCmd, bootstrapCmd, authPath, err := StartLinuxVNCServer(":0", 5901, "high", "secret")
	if err != nil {
		t.Fatalf("StartLinuxVNCServer returned error: %v", err)
	}
	if cmd != primaryCmd {
		t.Fatalf("cmd=%p, want %p", cmd, primaryCmd)
	}
	if xvfbCmd != nil {
		t.Fatalf("expected no Xvfb command, got %v", xvfbCmd)
	}
	if bootstrapCmd != nil {
		t.Fatalf("expected no bootstrap command, got %v", bootstrapCmd)
	}
	if authPath != "/tmp/auth-primary" {
		t.Fatalf("authPath=%q, want /tmp/auth-primary", authPath)
	}
	if launchCalls != 1 {
		t.Fatalf("launchCalls=%d, want 1", launchCalls)
	}
}

func TestStartLinuxVNCServerIgnoresNonX11DisplaySelection(t *testing.T) {
	originalLaunch := LaunchDesktopVNCReady
	originalStartXvfb := StartDesktopXvfb
	originalFind := FindDesktopFreeDisplay
	originalBootstrap := StartDesktopBootstrap
	originalCollectUserSessions := system.CollectUserSessionsFn
	t.Cleanup(func() {
		LaunchDesktopVNCReady = originalLaunch
		StartDesktopXvfb = originalStartXvfb
		FindDesktopFreeDisplay = originalFind
		StartDesktopBootstrap = originalBootstrap
		system.CollectUserSessionsFn = originalCollectUserSessions
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }

	lockFile := "/tmp/.X0-lock"
	if err := os.WriteFile(lockFile, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("failed to create mock lock file: %v", err)
	}
	defer os.Remove(lockFile)

	primaryCmd := &exec.Cmd{}
	LaunchDesktopVNCReady = func(display string, port int, quality, vncPassword, xauthPath string, timeout time.Duration) (*exec.Cmd, string, string, error) {
		if display != ":0" {
			t.Fatalf("expected invalid monitor label to resolve to preferred X display, got %q", display)
		}
		return primaryCmd, "/tmp/auth-primary", "", nil
	}
	StartDesktopXvfb = func(int, int, int) (*exec.Cmd, string, error) {
		t.Fatal("did not expect Xvfb fallback when :0 is available")
		return nil, "", nil
	}
	StartDesktopBootstrap = func(string, string) (*exec.Cmd, error) {
		t.Fatal("did not expect fallback bootstrap when :0 is available")
		return nil, nil
	}

	cmd, xvfbCmd, bootstrapCmd, authPath, err := StartLinuxVNCServer("DP-1", 5901, "medium", "")
	if err != nil {
		t.Fatalf("StartLinuxVNCServer returned error: %v", err)
	}
	if cmd != primaryCmd {
		t.Fatalf("cmd=%p, want %p", cmd, primaryCmd)
	}
	if xvfbCmd != nil {
		t.Fatalf("expected no Xvfb command, got %v", xvfbCmd)
	}
	if bootstrapCmd != nil {
		t.Fatalf("expected no bootstrap command, got %v", bootstrapCmd)
	}
	if authPath != "/tmp/auth-primary" {
		t.Fatalf("authPath=%q, want /tmp/auth-primary", authPath)
	}
}

func TestStartLinuxVNCServerFallsBackToXvfbOnDisplayError(t *testing.T) {
	originalLaunch := LaunchDesktopVNCReady
	originalStartXvfb := StartDesktopXvfb
	originalFind := FindDesktopFreeDisplay
	originalBootstrap := StartDesktopBootstrap
	originalCollectUserSessions := system.CollectUserSessionsFn
	t.Cleanup(func() {
		LaunchDesktopVNCReady = originalLaunch
		StartDesktopXvfb = originalStartXvfb
		FindDesktopFreeDisplay = originalFind
		StartDesktopBootstrap = originalBootstrap
		system.CollectUserSessionsFn = originalCollectUserSessions
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }

	// Create lock file so display :0 is considered usable (first attempt runs).
	lockFile := "/tmp/.X0-lock"
	if err := os.WriteFile(lockFile, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("failed to create mock lock file: %v", err)
	}
	defer os.Remove(lockFile)

	primaryErr := errors.New("cannot open display :0")
	fallbackCmd := &exec.Cmd{}
	xvfbCmd := &exec.Cmd{}
	bootstrapCmd := &exec.Cmd{}
	launchCalls := 0

	LaunchDesktopVNCReady = func(display string, port int, quality, vncPassword, xauthPath string, timeout time.Duration) (*exec.Cmd, string, string, error) {
		launchCalls++
		switch launchCalls {
		case 1:
			if display != ":0" {
				t.Fatalf("first display=%q, want :0", display)
			}
			return nil, "", "", primaryErr
		case 2:
			if display != ":97" {
				t.Fatalf("fallback display=%q, want :97", display)
			}
			return fallbackCmd, "/tmp/auth-fallback", "", nil
		default:
			t.Fatalf("unexpected launch call %d", launchCalls)
			return nil, "", "", nil
		}
	}
	FindDesktopFreeDisplay = func() int { return 97 }
	StartDesktopXvfb = func(display, width, height int) (*exec.Cmd, string, error) {
		if display != 97 || width != 1920 || height != 1080 {
			t.Fatalf("unexpected Xvfb args display=%d width=%d height=%d", display, width, height)
		}
		return xvfbCmd, "", nil
	}
	StartDesktopBootstrap = func(display, xauthPath string) (*exec.Cmd, error) {
		if display != ":97" {
			t.Fatalf("unexpected bootstrap display=%q", display)
		}
		if xauthPath != "" {
			t.Fatalf("expected empty xauth path, got %q", xauthPath)
		}
		return bootstrapCmd, nil
	}

	cmd, gotXvfb, gotBootstrap, authPath, err := StartLinuxVNCServer(":0", 5901, "medium", "")
	if err != nil {
		t.Fatalf("StartLinuxVNCServer returned error: %v", err)
	}
	if cmd != fallbackCmd {
		t.Fatalf("cmd=%p, want %p", cmd, fallbackCmd)
	}
	if gotXvfb != xvfbCmd {
		t.Fatalf("xvfbCmd=%p, want %p", gotXvfb, xvfbCmd)
	}
	if gotBootstrap != bootstrapCmd {
		t.Fatalf("bootstrapCmd=%p, want %p", gotBootstrap, bootstrapCmd)
	}
	if authPath != "/tmp/auth-fallback" {
		t.Fatalf("authPath=%q, want /tmp/auth-fallback", authPath)
	}
	if launchCalls != 2 {
		t.Fatalf("launchCalls=%d, want 2", launchCalls)
	}
}

func TestStartLinuxVNCServerSkipsToXvfbOnHeadless(t *testing.T) {
	originalLaunch := LaunchDesktopVNCReady
	originalStartXvfb := StartDesktopXvfb
	originalFind := FindDesktopFreeDisplay
	originalBootstrap := StartDesktopBootstrap
	originalCollectUserSessions := system.CollectUserSessionsFn
	originalDetectSession := DetectDesktopSessionFn
	t.Cleanup(func() {
		LaunchDesktopVNCReady = originalLaunch
		StartDesktopXvfb = originalStartXvfb
		FindDesktopFreeDisplay = originalFind
		StartDesktopBootstrap = originalBootstrap
		system.CollectUserSessionsFn = originalCollectUserSessions
		DetectDesktopSessionFn = originalDetectSession
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Type: DesktopSessionTypeHeadless, Backend: DesktopBackendHeadless}
	}

	// No lock file for :0 → headless, should skip first attempt entirely.
	os.Remove("/tmp/.X0-lock")

	fallbackCmd := &exec.Cmd{}
	xvfbCmd := &exec.Cmd{}
	bootstrapCmd := &exec.Cmd{}
	launchCalls := 0

	LaunchDesktopVNCReady = func(display string, port int, quality, vncPassword, xauthPath string, timeout time.Duration) (*exec.Cmd, string, string, error) {
		launchCalls++
		if launchCalls == 1 {
			// Should only be called once (for the Xvfb display), not for :0.
			if display != ":96" {
				t.Fatalf("expected Xvfb display :96, got %q", display)
			}
			return fallbackCmd, "/tmp/auth-xvfb", "", nil
		}
		t.Fatalf("unexpected launch call %d", launchCalls)
		return nil, "", "", nil
	}
	FindDesktopFreeDisplay = func() int { return 96 }
	StartDesktopXvfb = func(display, width, height int) (*exec.Cmd, string, error) {
		if display != 96 {
			t.Fatalf("unexpected Xvfb display=%d", display)
		}
		return xvfbCmd, "/tmp/xauth-96.xauth", nil
	}
	StartDesktopBootstrap = func(display, xauthPath string) (*exec.Cmd, error) {
		if xauthPath != "/tmp/xauth-96.xauth" {
			t.Fatalf("unexpected bootstrap xauth=%q", xauthPath)
		}
		return bootstrapCmd, nil
	}

	cmd, gotXvfb, gotBootstrap, authPath, err := StartLinuxVNCServer("", 5901, "medium", "pw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd != fallbackCmd {
		t.Fatal("expected Xvfb fallback VNC cmd")
	}
	if gotXvfb != xvfbCmd {
		t.Fatal("expected Xvfb cmd")
	}
	if gotBootstrap != bootstrapCmd {
		t.Fatal("expected bootstrap cmd")
	}
	if authPath != "/tmp/auth-xvfb" {
		t.Fatalf("authPath=%q, want /tmp/auth-xvfb", authPath)
	}
	if launchCalls != 1 {
		t.Fatalf("launchCalls=%d, want 1 (only Xvfb display)", launchCalls)
	}
}

func TestStartLinuxVNCServerReturnsPrimaryErrorWhenDisplayIsHealthyButStartupFails(t *testing.T) {
	originalLaunch := LaunchDesktopVNCReady
	originalStartXvfb := StartDesktopXvfb
	originalFind := FindDesktopFreeDisplay
	originalBootstrap := StartDesktopBootstrap
	originalCollectUserSessions := system.CollectUserSessionsFn
	t.Cleanup(func() {
		LaunchDesktopVNCReady = originalLaunch
		StartDesktopXvfb = originalStartXvfb
		FindDesktopFreeDisplay = originalFind
		StartDesktopBootstrap = originalBootstrap
		system.CollectUserSessionsFn = originalCollectUserSessions
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }

	// Create lock file so :0 is considered usable (triggers first attempt).
	lockFile := "/tmp/.X0-lock"
	if err := os.WriteFile(lockFile, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("failed to create mock lock file: %v", err)
	}
	defer os.Remove(lockFile)

	LaunchDesktopVNCReady = func(display string, port int, quality, vncPassword, xauthPath string, timeout time.Duration) (*exec.Cmd, string, string, error) {
		return nil, "", "", errors.New("x11vnc not found")
	}
	StartDesktopXvfb = func(int, int, int) (*exec.Cmd, string, error) {
		t.Fatal("did not expect Xvfb fallback for non-display startup error")
		return nil, "", nil
	}
	StartDesktopBootstrap = func(string, string) (*exec.Cmd, error) {
		t.Fatal("did not expect fallback bootstrap for non-display startup error")
		return nil, nil
	}

	_, _, _, _, err := StartLinuxVNCServer(":0", 5901, "medium", "")
	if err == nil {
		t.Fatal("expected startup error")
	}
	if !strings.Contains(err.Error(), "x11vnc not found") {
		t.Fatalf("error=%q, want x11vnc not found", err)
	}
}

func TestStartLinuxVNCServerBootstrapFailureStillStartsVNC(t *testing.T) {
	originalLaunch := LaunchDesktopVNCReady
	originalStartXvfb := StartDesktopXvfb
	originalFind := FindDesktopFreeDisplay
	originalBootstrap := StartDesktopBootstrap
	originalCollectUserSessions := system.CollectUserSessionsFn
	t.Cleanup(func() {
		LaunchDesktopVNCReady = originalLaunch
		StartDesktopXvfb = originalStartXvfb
		FindDesktopFreeDisplay = originalFind
		StartDesktopBootstrap = originalBootstrap
		system.CollectUserSessionsFn = originalCollectUserSessions
	})
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }

	// Create lock file so :0 is considered usable (triggers first attempt → display error → Xvfb).
	lockFile := "/tmp/.X0-lock"
	if err := os.WriteFile(lockFile, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("failed to create mock lock file: %v", err)
	}
	defer os.Remove(lockFile)

	primaryErr := errors.New("cannot open display :0")
	fallbackCmd := &exec.Cmd{}
	xvfbCmd := &exec.Cmd{}
	launchCalls := 0

	LaunchDesktopVNCReady = func(display string, port int, quality, vncPassword, xauthPath string, timeout time.Duration) (*exec.Cmd, string, string, error) {
		launchCalls++
		if launchCalls == 1 {
			return nil, "", "", primaryErr
		}
		return fallbackCmd, "/tmp/auth-fb", "", nil
	}
	FindDesktopFreeDisplay = func() int { return 95 }
	StartDesktopXvfb = func(display, width, height int) (*exec.Cmd, string, error) {
		return xvfbCmd, "", nil
	}
	StartDesktopBootstrap = func(display, xauthPath string) (*exec.Cmd, error) {
		if xauthPath != "" {
			t.Fatalf("expected empty xauth path, got %q", xauthPath)
		}
		return nil, fmt.Errorf("xterm not found")
	}

	cmd, gotXvfb, gotBootstrap, _, err := StartLinuxVNCServer(":0", 5901, "medium", "")
	if err != nil {
		t.Fatalf("expected success despite bootstrap failure, got: %v", err)
	}
	if cmd != fallbackCmd {
		t.Fatalf("expected fallback VNC cmd")
	}
	if gotXvfb != xvfbCmd {
		t.Fatalf("expected Xvfb cmd")
	}
	if gotBootstrap != nil {
		t.Fatalf("expected nil bootstrap cmd when xterm failed")
	}
}
