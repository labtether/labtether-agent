package remoteaccess

import (
	"context"
	"fmt"
	"github.com/labtether/labtether-agent/internal/x11input"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const testX11Keymap = `There are 4 KeySyms per KeyCode; KeyCodes range from 8 to 255.
    KeyCode	Keysym (Keysym)	...
    Value  	Value   (Name) 	...
8 0x0038 (8) 0x0000 (NoSymbol)
9 0xff1b (Escape) 0x0000 (NoSymbol)
38 0x0061 (a) 0x0041 (A)
50 0xffe1 (Shift_L) 0x0000 (NoSymbol)
62 0xffe2 (Shift_R) 0x0000 (NoSymbol)
100 0x0000 (NoSymbol) 0xffe1 (Shift_L)
101 0x10000005 (no name)
102
`

func TestWebRTCX11KeymapResolvesPhysicalAliases(t *testing.T) {
	for key, want := range map[string]uint8{"Shift_L": 50, "0xffe1": 50, "Shift_R": 62, "a": 38, "A": 38, "0x61": 38, "8": 8, "Escape": 9, "0x10000005": 101} {
		got, err := resolveX11Keycode([]byte(testX11Keymap), key)
		if err != nil || got != want {
			t.Fatalf("resolve %q = %d, %v; want %d", key, got, err, want)
		}
		arg, err := x11RawKeyArgument(WebRTCInputEvent{x11Keycode: got})
		if err != nil || arg != strconv.Itoa(int(want)) {
			t.Fatalf("raw code %d = %q, %v", got, arg, err)
		}
	}
	for _, malformed := range []string{"", "7 0x0061 (a)", "256 0x0061 (a)", "38 0x0061 (a)\n38 0x0062 (b)", "38 0x0061", "38 0xzz (a)", "38 0x0061 a", strings.Repeat(" ", maxWebRTCX11KeymapBytes+1)} {
		if _, err := resolveX11Keycode([]byte(malformed), "a"); err == nil {
			t.Fatalf("accepted malformed or incomplete map: %.80q", malformed)
		}
	}
	if _, err := resolveX11Keycode([]byte(testX11Keymap), "NoSuchKey"); err == nil {
		t.Fatal("unsupported symbol did not fail")
	}
}

// This is a real child process, so output limits, sanitized display selection
// and process completion exercise the same owner as the installed helper.
func TestWebRTCX11CommandPath(t *testing.T) {
	if len(os.Args) > 2 && os.Args[len(os.Args)-2] == "x11-command-helper" {
		switch os.Args[len(os.Args)-1] {
		case "keymap":
			if os.Getenv("DISPLAY") != ":17" || os.Getenv("XAUTHORITY") != "/session/auth" {
				os.Exit(8)
			}
			fmt.Print(testX11Keymap)
		case "overflow":
			fmt.Print(strings.Repeat("x", maxWebRTCX11KeymapBytes+1))
		case "fail":
			os.Exit(9)
		}
		exitTestHelper(0)
	}
	originalCommand, originalLookPath := NewWebRTCSecurityCommand, WebRTCLookPath
	originalInternal := NewWebRTCInternalX11Command
	t.Cleanup(func() { NewWebRTCInternalX11Command = originalInternal })
	NewWebRTCInternalX11Command = func(args ...string) (*exec.Cmd, error) { return NewWebRTCSecurityCommand(x11input.PolicyName, args...) }
	t.Cleanup(func() { NewWebRTCSecurityCommand, WebRTCLookPath = originalCommand, originalLookPath })
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	mode := "keymap"
	NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
		commands = append(commands, append([]string{name}, args...))
		childMode := "ok"
		if name == "xmodmap" && len(args) == 1 && args[0] == "-pk" {
			childMode = mode
		}
		return exec.Command(executable, "-test.run=^TestWebRTCX11CommandPath$", "--", "x11-command-helper", childMode), nil
	}
	event, err := resolveWebRTCX11Input(context.Background(), WebRTCInputEvent{Type: "keydown", Code: "ShiftRight"}, ":17", "/session/auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := injectSingleInputContext(context.Background(), event, ":17", "/session/auth", nil); err != nil {
		t.Fatal(err)
	}
	event.Type = "keyup"
	if err := releaseWebRTCInputs(context.Background(), []WebRTCInputEvent{event}, ":17", "/session/auth", nil); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"xmodmap", "-pk"}, {x11input.PolicyName, "down", "62"}, {x11input.PolicyName, "up", "62"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("physical calls=%v, want %v", commands, want)
	}
	commands = nil
	if err := InjectSingleInput(WebRTCInputEvent{Type: "keydown", KeyCode: 0x123456}, ":17", "/session/auth", nil); err == nil {
		t.Fatal("unknown key accepted")
	}
	if len(commands) != 1 || commands[0][0] != "xmodmap" {
		t.Fatalf("unknown key reached injection: %v", commands)
	}
	mode = "overflow"
	if _, err := resolveWebRTCX11Input(context.Background(), WebRTCInputEvent{Type: "keydown", Code: "KeyA"}, ":17", "/session/auth"); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized map error=%v", err)
	}
	WebRTCLookPath = func(name string) (string, error) { return name, nil }
	commands = nil
	if reason := webRTCX11KeymapUnavailableReason(DesktopSessionInfo{}); reason != "" {
		t.Fatalf("working probe: %s", reason)
	}
	if !reflect.DeepEqual(commands, [][]string{{"xmodmap", "-version"}}) {
		t.Fatalf("probe requires display or mutates keymap: %v", commands)
	}
	NewWebRTCSecurityCommand = func(string, ...string) (*exec.Cmd, error) {
		return exec.Command(executable, "-test.run=^TestWebRTCX11CommandPath$", "--", "x11-command-helper", "fail"), nil
	}
	if reason := webRTCX11KeymapUnavailableReason(DesktopSessionInfo{}); reason != webrtcReasonX11KeymapToolProbeFailed {
		t.Fatalf("failed probe reason=%s", reason)
	}
	WebRTCLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if reason := webRTCX11KeymapUnavailableReason(DesktopSessionInfo{}); reason != webrtcReasonX11KeymapToolMissing {
		t.Fatalf("missing tool reason=%s", reason)
	}
}

func TestWebRTCX11CapabilitiesRequiresKeymapTool(t *testing.T) {
	originalCommand, originalLookPath := NewWebRTCSecurityCommand, WebRTCLookPath
	originalGOOS, originalSession := WebRTCRuntimeGOOS, DetectDesktopSessionFn
	t.Cleanup(func() {
		NewWebRTCSecurityCommand, WebRTCLookPath = originalCommand, originalLookPath
		WebRTCRuntimeGOOS, DetectDesktopSessionFn = originalGOOS, originalSession
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	WebRTCRuntimeGOOS = "linux"
	for _, sessionType := range []string{DesktopSessionTypeX11, DesktopSessionTypeHeadless} {
		DetectDesktopSessionFn = func() DesktopSessionInfo { return DesktopSessionInfo{Type: sessionType, Display: ":17"} }
		for _, failure := range []string{"missing", "failed", "blocked", ""} {
			t.Setenv("LABTETHER_EXEC_ALLOWLIST_MODE", "true")
			t.Setenv("LABTETHER_EXEC_ALLOWED_BINARIES", "")
			if failure == "blocked" {
				t.Setenv("LABTETHER_EXEC_ALLOWED_BINARIES", "xdotool,xmodmap")
			}
			WebRTCLookPath = func(name string) (string, error) {
				if name == "xmodmap" && failure == "missing" {
					return "", exec.ErrNotFound
				}
				return name, nil
			}
			NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
				mode := "ok"
				if name == "xmodmap" && failure == "failed" {
					mode = "fail"
				}
				return exec.Command(executable, "-test.run=^TestWebRTCX11CommandPath$", "--", "x11-command-helper", mode), nil
			}
			caps := DetectWebRTCCapabilitiesWithConfig(WebRTCConfig{})
			want := ""
			if failure == "missing" {
				want = webrtcReasonX11KeymapToolMissing
			}
			if failure == "failed" {
				want = webrtcReasonX11KeymapToolProbeFailed
			}
			if failure == "blocked" {
				want = webrtcReasonX11InputHelperBlocked
			}
			if caps.UnavailableReason != want || caps.Available != (failure == "") {
				t.Fatalf("session=%s failure=%s capabilities=%+v", sessionType, failure, caps)
			}
		}
	}
}
