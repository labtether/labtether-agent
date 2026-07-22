package remoteaccess

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func preserveWebRTCInputHooks(t *testing.T) {
	t.Helper()
	originalGOOS := WebRTCRuntimeGOOS
	originalLookPath := WebRTCLookPath
	originalNewCommand := NewWebRTCSecurityCommand
	originalDetectSession := DetectDesktopSessionFn
	t.Cleanup(func() {
		WebRTCRuntimeGOOS = originalGOOS
		WebRTCLookPath = originalLookPath
		NewWebRTCSecurityCommand = originalNewCommand
		DetectDesktopSessionFn = originalDetectSession
	})
}

func TestDetectWebRTCCapabilitiesRequiresWorkingInputBackend(t *testing.T) {
	tests := []struct {
		name        string
		session     DesktopSessionInfo
		config      WebRTCConfig
		missingTool string
		failingTool string
		wantReason  string
	}{
		{
			name:        "X11 xdotool missing",
			session:     DesktopSessionInfo{Type: DesktopSessionTypeX11, Backend: DesktopBackendX11, Display: ":1"},
			missingTool: "xdotool",
			wantReason:  webrtcReasonX11InputToolMissing,
		},
		{
			name:        "X11 xdotool probe fails",
			session:     DesktopSessionInfo{Type: DesktopSessionTypeX11, Backend: DesktopBackendX11, Display: ":1"},
			failingTool: "xdotool",
			wantReason:  webrtcReasonX11InputToolProbeFailed,
		},
		{
			name:        "Wayland ydotool missing",
			session:     DesktopSessionInfo{Type: DesktopSessionTypeWayland, Backend: DesktopBackendWaylandPipeWire, XDGRuntimeDir: "/run/user/1000"},
			config:      WebRTCConfig{WaylandExperimentalEnabled: true, WaylandPipeWireNodeID: "42", WaylandInputBackend: "auto"},
			missingTool: "ydotool",
			wantReason:  webrtcReasonWaylandInputToolMissing,
		},
		{
			name:        "Wayland ydotool probe fails",
			session:     DesktopSessionInfo{Type: DesktopSessionTypeWayland, Backend: DesktopBackendWaylandPipeWire, XDGRuntimeDir: "/run/user/1000"},
			config:      WebRTCConfig{WaylandExperimentalEnabled: true, WaylandPipeWireNodeID: "42", WaylandInputBackend: "ydotool"},
			failingTool: "ydotool",
			wantReason:  webrtcReasonWaylandInputToolProbeFailed,
		},
		{
			name:       "Wayland input explicitly disabled",
			session:    DesktopSessionInfo{Type: DesktopSessionTypeWayland, Backend: DesktopBackendWaylandPipeWire, XDGRuntimeDir: "/run/user/1000"},
			config:     WebRTCConfig{WaylandExperimentalEnabled: true, WaylandPipeWireNodeID: "42", WaylandInputBackend: "none"},
			wantReason: webrtcReasonWaylandInputDisabled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			preserveWebRTCInputHooks(t)
			WebRTCRuntimeGOOS = "linux"
			DetectDesktopSessionFn = func() DesktopSessionInfo { return tc.session }
			WebRTCLookPath = func(name string) (string, error) {
				if name == tc.missingTool {
					return "", errors.New("missing")
				}
				return "/usr/bin/" + name, nil
			}
			NewWebRTCSecurityCommand = func(name string, _ ...string) (*exec.Cmd, error) {
				if strings.HasSuffix(name, "/"+tc.failingTool) && tc.failingTool != "" {
					return exec.Command("/bin/sh", "-c", "printf 'probe failed' >&2; exit 9"), nil
				}
				return exec.Command("/bin/sh", "-c", "exit 0"), nil
			}

			caps := DetectWebRTCCapabilitiesWithConfig(tc.config)
			if caps.Available {
				t.Fatalf("capabilities advertised full control with broken input: %+v", caps)
			}
			if caps.UnavailableReason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", caps.UnavailableReason, tc.wantReason)
			}
		})
	}
}

func TestProbeWebRTCInputToolUsesYdotoolDebugAndWaylandSessionEnv(t *testing.T) {
	preserveWebRTCInputHooks(t)
	t.Setenv("DISPLAY", ":99")
	t.Setenv("XAUTHORITY", "/tmp/ambient-xauth")
	WebRTCLookPath = func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}
	var gotName string
	var gotArgs []string
	NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.Command("/bin/sh", "-c", `
			test "$XDG_RUNTIME_DIR" = "/run/user/1000" &&
			test "$WAYLAND_DISPLAY" = "wayland-7" &&
			test -z "$DISPLAY" &&
			test -z "$XAUTHORITY"
		`), nil
	}

	missing, err := ProbeWebRTCInputTool("ydotool", DesktopSessionInfo{
		Type:           DesktopSessionTypeWayland,
		XDGRuntimeDir:  "/run/user/1000",
		WaylandDisplay: "wayland-7",
	})
	if missing || err != nil {
		t.Fatalf("ProbeWebRTCInputTool = missing %v, err %v", missing, err)
	}
	if gotName != "/usr/bin/ydotool" || !reflect.DeepEqual(gotArgs, []string{"debug"}) {
		t.Fatalf("probe command = %q %#v, want /usr/bin/ydotool debug", gotName, gotArgs)
	}
}

func TestProbeWebRTCInputToolUsesDisplayIndependentXdotoolVersionFlag(t *testing.T) {
	preserveWebRTCInputHooks(t)
	WebRTCLookPath = func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}
	var gotName string
	var gotArgs []string
	NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.Command("/bin/sh", "-c", "exit 0"), nil
	}

	missing, err := ProbeWebRTCInputTool("xdotool", DesktopSessionInfo{Type: DesktopSessionTypeHeadless})
	if missing || err != nil {
		t.Fatalf("ProbeWebRTCInputTool = missing %v, err %v", missing, err)
	}
	if gotName != "/usr/bin/xdotool" || !reflect.DeepEqual(gotArgs, []string{"--version"}) {
		t.Fatalf("probe command = %q %#v, want /usr/bin/xdotool --version", gotName, gotArgs)
	}
}

func TestInjectWaylandInputPreservesMouseDownAndUpState(t *testing.T) {
	preserveWebRTCInputHooks(t)
	var commands [][]string
	NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
		commands = append(commands, append([]string{name}, args...))
		return exec.Command("/bin/sh", "-c", "exit 0"), nil
	}
	sess := &WebRTCSession{
		inputBackend: "ydotool",
		sessionInfo: DesktopSessionInfo{
			Type:           DesktopSessionTypeWayland,
			WaylandDisplay: "wayland-1",
			XDGRuntimeDir:  "/run/user/1000",
		},
	}

	if err := InjectWaylandInputEvent(WebRTCInputEvent{Type: "mousedown", Button: 0}, sess); err != nil {
		t.Fatalf("mousedown: %v", err)
	}
	if err := InjectWaylandInputEvent(WebRTCInputEvent{Type: "mouseup", Button: 0}, sess); err != nil {
		t.Fatalf("mouseup: %v", err)
	}
	want := [][]string{{"ydotool", "click", "0x40"}, {"ydotool", "click", "0x80"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands mismatch:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestInjectWaylandInputUsesWheelEventsInsteadOfSideButtons(t *testing.T) {
	preserveWebRTCInputHooks(t)
	var commands [][]string
	NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
		commands = append(commands, append([]string{name}, args...))
		return exec.Command("/bin/sh", "-c", "exit 0"), nil
	}
	sess := &WebRTCSession{
		inputBackend: "ydotool",
		sessionInfo:  DesktopSessionInfo{Type: DesktopSessionTypeWayland},
	}

	if err := InjectWaylandInputEvent(WebRTCInputEvent{Type: "scroll", DeltaY: -100}, sess); err != nil {
		t.Fatalf("scroll up: %v", err)
	}
	if err := InjectWaylandInputEvent(WebRTCInputEvent{Type: "scroll", DeltaY: 100}, sess); err != nil {
		t.Fatalf("scroll down: %v", err)
	}
	want := [][]string{
		{"ydotool", "mousemove", "--wheel", "-x", "0", "-y", "1"},
		{"ydotool", "mousemove", "--wheel", "-x", "0", "-y", "-1"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands mismatch:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestInjectSingleInputSurfacesCommandBuildAndRunFailures(t *testing.T) {
	t.Run("command build", func(t *testing.T) {
		preserveWebRTCInputHooks(t)
		NewWebRTCSecurityCommand = func(string, ...string) (*exec.Cmd, error) {
			return nil, errors.New("policy denied")
		}
		err := InjectSingleInput(WebRTCInputEvent{Type: "mousemove", X: 1, Y: 2}, ":1", "/tmp/xauth", nil)
		if err == nil || !strings.Contains(err.Error(), "policy denied") {
			t.Fatalf("error = %v, want command-build failure", err)
		}
	})

	t.Run("command run", func(t *testing.T) {
		preserveWebRTCInputHooks(t)
		NewWebRTCSecurityCommand = func(string, ...string) (*exec.Cmd, error) {
			return exec.Command("/bin/sh", "-c", "printf 'input backend denied' >&2; exit 7"), nil
		}
		err := InjectSingleInput(WebRTCInputEvent{Type: "mousemove", X: 1, Y: 2}, ":1", "/tmp/xauth", nil)
		if err == nil || !strings.Contains(err.Error(), "input backend denied") {
			t.Fatalf("error = %v, want bounded process failure detail", err)
		}
	})
}

func TestInjectInputEventsLogsCommandFailure(t *testing.T) {
	preserveWebRTCInputHooks(t)
	NewWebRTCSecurityCommand = func(string, ...string) (*exec.Cmd, error) {
		return nil, errors.New("input tool unavailable")
	}

	var logs bytes.Buffer
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
	})

	ch := make(chan WebRTCInputEvent, 1)
	ch <- WebRTCInputEvent{Type: "mousemove", X: 1, Y: 2}
	close(ch)
	InjectInputEvents(context.Background(), ch, ":1", "/tmp/xauth", &WebRTCSession{
		sessionID:      "session-1",
		desktopBackend: DesktopBackendX11,
	})
	if got := logs.String(); !strings.Contains(got, "session=session-1") ||
		!strings.Contains(got, "event=mousemove") ||
		!strings.Contains(got, "input tool unavailable") {
		t.Fatalf("failure log missing safe diagnostic fields: %q", got)
	}
}
