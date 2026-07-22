//go:build linux

package sysconfig

import (
	"context"
	"os/exec"
	"testing"
)

func TestPlatformListDisplaysUsesDetectedDisplayEnvironment(t *testing.T) {
	restoreDisplayListHooks(t)

	DetectDesktopSessionTypeFn = func() string { return DesktopSessionTypeX11 }
	PreferredX11DisplayFn = func() string { return ":2" }
	wokenDisplay := ""
	WakeX11DisplayFn = func(display, xauthPath string) {
		wokenDisplay = display
		if xauthPath != "" {
			t.Fatalf("wake xauth=%q, want discovery", xauthPath)
		}
	}
	BuildX11ClientEnvFn = func(display, xauthPath string) []string {
		if display != ":2" {
			t.Fatalf("env display=%q, want :2", display)
		}
		if xauthPath != "" {
			t.Fatalf("env xauth=%q, want discovery", xauthPath)
		}
		return []string{
			"PATH=/usr/bin:/bin",
			"DISPLAY=:2",
			"XAUTHORITY=/run/lightdm/root/:2",
		}
	}
	NewDisplayListCommand = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		if name != "xrandr" || len(args) != 1 || args[0] != "--listmonitors" {
			t.Fatalf("command=%q args=%v, want xrandr --listmonitors", name, args)
		}
		return exec.CommandContext(ctx, "/bin/sh", "-c", `
			test "$DISPLAY" = ":2"
			test "$XAUTHORITY" = "/run/lightdm/root/:2"
			printf 'Monitors: 1\n 0: +*Virtual-1 1280/325x800/203+0+0  Virtual-1\n'
		`), nil
	}

	displays, err := PlatformListDisplays()
	if err != nil {
		t.Fatalf("PlatformListDisplays() error: %v", err)
	}
	if wokenDisplay != ":2" {
		t.Fatalf("woken display=%q, want :2", wokenDisplay)
	}
	if len(displays) != 1 {
		t.Fatalf("display count=%d, want 1", len(displays))
	}
	if displays[0].Name != "Virtual-1" || displays[0].Width != 1280 || displays[0].Height != 800 || !displays[0].Primary {
		t.Fatalf("unexpected display: %+v", displays[0])
	}
}

func TestPlatformListDisplaysReturnsEmptyWithoutX11Session(t *testing.T) {
	restoreDisplayListHooks(t)

	DetectDesktopSessionTypeFn = func() string { return "headless" }
	preferredCalled := false
	PreferredX11DisplayFn = func() string {
		preferredCalled = true
		return ":0"
	}
	commandCalled := false
	NewDisplayListCommand = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		commandCalled = true
		return exec.CommandContext(ctx, "/bin/false"), nil
	}

	displays, err := PlatformListDisplays()
	if err != nil {
		t.Fatalf("PlatformListDisplays() error: %v", err)
	}
	if len(displays) != 0 {
		t.Fatalf("display count=%d, want 0", len(displays))
	}
	if preferredCalled || commandCalled {
		t.Fatalf("headless display probe ran unexpectedly: preferred=%v command=%v", preferredCalled, commandCalled)
	}
}

func TestPlatformListDisplaysReturnsEmptyWithoutDetectedDisplay(t *testing.T) {
	restoreDisplayListHooks(t)

	DetectDesktopSessionTypeFn = func() string { return DesktopSessionTypeX11 }
	PreferredX11DisplayFn = func() string { return "" }
	commandCalled := false
	NewDisplayListCommand = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		commandCalled = true
		return exec.CommandContext(ctx, "/bin/false"), nil
	}

	displays, err := PlatformListDisplays()
	if err != nil {
		t.Fatalf("PlatformListDisplays() error: %v", err)
	}
	if len(displays) != 0 {
		t.Fatalf("display count=%d, want 0", len(displays))
	}
	if commandCalled {
		t.Fatal("xrandr command ran without a detected display")
	}
}

func restoreDisplayListHooks(t *testing.T) {
	t.Helper()
	originalDetect := DetectDesktopSessionTypeFn
	originalPreferred := PreferredX11DisplayFn
	originalWake := WakeX11DisplayFn
	originalBuildEnv := BuildX11ClientEnvFn
	originalCommand := NewDisplayListCommand
	t.Cleanup(func() {
		DetectDesktopSessionTypeFn = originalDetect
		PreferredX11DisplayFn = originalPreferred
		WakeX11DisplayFn = originalWake
		BuildX11ClientEnvFn = originalBuildEnv
		NewDisplayListCommand = originalCommand
	})
}
