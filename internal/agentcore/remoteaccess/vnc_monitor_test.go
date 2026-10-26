package remoteaccess

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

const vncMonitorFixture = "Monitors: 2\n 0: +*DP-1 3840/700x2160/400+0+0 DP-1\n 1: +HDMI-1 1920/500x1080/300+3840+0 HDMI-1\n"

func TestVNCMonitorSelectionStartsExactCropOnActiveScreen(t *testing.T) {
	originalDetect, originalCommand := DetectDesktopSessionFn, NewVNCMonitorCommand
	originalDiscover, originalLaunch := DiscoverDisplayXAuthorityFn, LaunchDesktopVNCMonitorReady
	originalWake := NewX11UtilityCommand
	t.Cleanup(func() {
		DetectDesktopSessionFn, NewVNCMonitorCommand = originalDetect, originalCommand
		DiscoverDisplayXAuthorityFn, LaunchDesktopVNCMonitorReady = originalDiscover, originalLaunch
		NewX11UtilityCommand = originalWake
	})
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":93.1"}
	}
	DiscoverDisplayXAuthorityFn = func(string) string { return "/fixture/xauth" }
	wakes := 0
	NewX11UtilityCommand = func(string, ...string) (*exec.Cmd, error) {
		wakes++
		return exec.Command(os.Args[0], "-test.run=^TestVNCMonitorMetadataHelper$", "--", "--wake"), nil
	}
	var queries []string
	NewVNCMonitorCommand = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		if name != "xrandr" || len(args) != 1 {
			t.Fatalf("unexpected metadata command: %s %v", name, args)
		}
		queries = append(queries, args[0])
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVNCMonitorMetadataHelper$", "--", args[0]), nil
	}
	wantCommand := &exec.Cmd{}
	LaunchDesktopVNCMonitorReady = func(display string, port int, quality, password, xauth string, timeout time.Duration, clip string) (*exec.Cmd, string, string, error) {
		if wakes != 4 {
			t.Fatalf("selected monitor did not finish its wake sequence: %d commands", wakes)
		}
		if display != ":93.1" || clip != "1920x1080+3840+0" || xauth != "/fixture/xauth" {
			t.Fatalf("wrong selected capture: %q %q %q", display, clip, xauth)
		}
		args := buildX11VNCArgsWithClip(display, port, quality, "/fixture/rfbauth", xauth, clip)
		if !reflect.DeepEqual(args[len(args)-2:], []string{"-clip", "1920x1080+3840+0"}) || args[1] != display {
			t.Fatalf("missing crop/display in x11vnc command: %v", args)
		}
		return wantCommand, "/fixture/rfbauth", "", nil
	}
	cmd, xvfb, bootstrap, auth, err := StartLinuxVNCServer("HDMI-1", 5901, "medium", "")
	if err != nil || cmd != wantCommand || xvfb != nil || bootstrap != nil || auth != "/fixture/rfbauth" {
		t.Fatalf("selected monitor start = %v %v %v %q %v", cmd, xvfb, bootstrap, auth, err)
	}
	if !reflect.DeepEqual(queries, []string{"--current", "--listmonitors"}) {
		t.Fatalf("metadata queries = %v", queries)
	}
	LaunchDesktopVNCMonitorReady = func(string, int, string, string, string, time.Duration, string) (*exec.Cmd, string, string, error) {
		return nil, "", "", errors.New("selected capture unavailable")
	}
	_, xvfb, bootstrap, _, err = StartLinuxVNCServer("HDMI-1", 5901, "medium", "")
	if err == nil || !strings.Contains(err.Error(), "selected capture unavailable") || xvfb != nil || bootstrap != nil {
		t.Fatalf("selected monitor launch failure changed desktop: %v", err)
	}
}

func TestVNCMonitorSelectionRejectsUnknownAmbiguousOrOutOfBounds(t *testing.T) {
	monitors := sysconfig.ParseXrandrMonitors(vncMonitorFixture)
	for _, tc := range []struct {
		name     string
		monitors []protocol.DisplayInfo
	}{
		{"missing", monitors},
		{"HDMI-1", append(append([]protocol.DisplayInfo{}, monitors...), monitors[1])},
		{"bad", []protocol.DisplayInfo{{Name: "bad", Width: 10, Height: 10, OffsetX: -1}}},
		{"bad", []protocol.DisplayInfo{{Name: "bad", Width: 1920, Height: 1080, OffsetX: 5000}}},
		{"bad", []protocol.DisplayInfo{{Name: "bad", Width: 0, Height: 1080}}},
		{"bad", []protocol.DisplayInfo{{Name: "bad", Width: 10, Height: 10, OffsetY: 2160}}},
	} {
		if clip, err := selectVNCMonitorClip(tc.name, tc.monitors, 5760, 2160); err == nil || clip != "" {
			t.Fatalf("invalid selected monitor accepted: %s %v -> %q %v", tc.name, tc.monitors, clip, err)
		}
	}
	if clip, err := selectVNCMonitorClip("HDMI-1", monitors, 5760, 2160); err != nil || clip != "1920x1080+3840+0" {
		t.Fatalf("edge-aligned monitor rejected: %q %v", clip, err)
	}
}

func TestX11ScreenAvailabilityUsesSameServerIdentity(t *testing.T) {
	originalDetect, originalSessions := DetectDesktopSessionFn, system.CollectUserSessionsFn
	t.Cleanup(func() {
		DetectDesktopSessionFn, system.CollectUserSessionsFn = originalDetect, originalSessions
	})
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":093247.0"}
	}
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) {
		t.Fatal("active X11 screen alias fell through to unrelated login enumeration")
		return nil, nil
	}
	if !IsDisplayAvailable(":93247.1") {
		t.Fatal("selected screen lost the active X server")
	}
}

func TestVNCMonitorMetadataHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	if os.Getenv("DISPLAY") != ":93.1" || os.Getenv("XAUTHORITY") != "/fixture/xauth" {
		os.Exit(2)
	}
	switch os.Args[len(os.Args)-1] {
	case "--current":
		_, _ = os.Stdout.WriteString("Screen 1: minimum 8 x 8, current 5760 x 2160, maximum 32767 x 32767\n")
	case "--listmonitors":
		_, _ = os.Stdout.WriteString(vncMonitorFixture)
	case "--wake":
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
