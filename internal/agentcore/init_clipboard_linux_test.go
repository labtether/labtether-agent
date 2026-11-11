//go:build linux

package agentcore

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/remoteaccess"
	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
)

// With no desktop session the clipboard must use only the agent's own Xvfb
// (remoteaccess tests cover that path with a live stand-in), never another X
// server a display scan finds: a local user could run one on :1 to read the
// viewer's pasted text or plant what the viewer copies.
func TestHeadlessClipboardUsesOnlyTheAgentsOwnXvfb(t *testing.T) {
	originalDetect := detectDesktopSessionFn
	originalActive := appendDetectedActiveDisplays
	originalXAuth := remoteaccess.DiscoverDisplayXAuthorityFn
	originalLookPath := sysconfig.ClipboardLookPath
	originalNewCommand := sysconfig.ClipboardNewCommand
	t.Cleanup(func() {
		detectDesktopSessionFn = originalDetect
		appendDetectedActiveDisplays = originalActive
		remoteaccess.DiscoverDisplayXAuthorityFn = originalXAuth
		sysconfig.ClipboardLookPath = originalLookPath
		sysconfig.ClipboardNewCommand = originalNewCommand
	})

	detectDesktopSessionFn = func() desktopSessionInfo { return desktopSessionInfo{Type: "headless"} }
	// Another local user's live X server at :1, as a display scan finds it.
	appendDetectedActiveDisplays = func(dst []string) []string { return append(dst, ":1") }
	remoteaccess.DiscoverDisplayXAuthorityFn = func(display string) string {
		if display == ":1" {
			return "/home/other/.Xauthority"
		}
		return ""
	}
	sysconfig.ClipboardLookPath = func(name string) (string, error) {
		if name == "xclip" {
			return "/usr/bin/xclip", nil
		}
		return "", errors.New("not installed")
	}
	// Stand in for xclip: print the display and cookie file it would use.
	sysconfig.ClipboardNewCommand = func(string, ...string) (*exec.Cmd, error) {
		return exec.Command("sh", "-c", `printf '%s %s' "$DISPLAY" "$XAUTHORITY"`), nil
	}
	read := func() string {
		t.Helper()
		text, _, err := sysconfig.PlatformClipboardRead("text")
		if err != nil {
			t.Fatalf("clipboard read: %v", err)
		}
		return text
	}

	// A recorded Xvfb whose process is gone is not the agent's display.
	dead := &exec.Cmd{}
	remoteaccess.RegisterAgentXvfb(dead, ":99", "/tmp/labtether-xauth-99.xauth")
	t.Cleanup(func() { remoteaccess.ForgetAgentXvfb(dead) })
	if got := read(); got != ":0 " {
		t.Fatalf("with no live agent Xvfb the clipboard used %q, want :0 and never the scanned :1", got)
	}
}
