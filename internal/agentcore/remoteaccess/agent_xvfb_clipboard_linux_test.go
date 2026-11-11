//go:build linux

package remoteaccess

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
)

// On a device without a desktop the clipboard went to :0, where nothing runs.
// It must reach the agent's own Xvfb with that display's cookie, and refuse in
// words while two Remote View sessions run.
func TestHeadlessClipboardReachesTheAgentsXvfb(t *testing.T) {
	isolateAgentXvfbs(t)
	originalDetect := sysconfig.DetectLinuxDesktopSessionFn
	originalAgentXvfb := sysconfig.AgentXvfbDisplayFn
	originalBuildEnv := sysconfig.BuildX11ClientEnvFn
	originalLookPath := sysconfig.ClipboardLookPath
	originalNewCommand := sysconfig.ClipboardNewCommand
	t.Cleanup(func() {
		sysconfig.DetectLinuxDesktopSessionFn = originalDetect
		sysconfig.AgentXvfbDisplayFn = originalAgentXvfb
		sysconfig.BuildX11ClientEnvFn = originalBuildEnv
		sysconfig.ClipboardLookPath = originalLookPath
		sysconfig.ClipboardNewCommand = originalNewCommand
	})
	sysconfig.DetectLinuxDesktopSessionFn = func() sysconfig.LinuxDesktopSessionInfo {
		return sysconfig.LinuxDesktopSessionInfo{Type: "headless"}
	}
	sysconfig.AgentXvfbDisplayFn = AgentXvfbDisplay
	sysconfig.BuildX11ClientEnvFn = BuildX11ClientEnv
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

	RegisterAgentXvfb(startXvfbStandIn(t, 99), ":99", "/tmp/labtether-xauth-99.xauth")
	text, _, err := sysconfig.PlatformClipboardRead("text")
	if err != nil || text != ":99 /tmp/labtether-xauth-99.xauth" {
		t.Fatalf("clipboard used %q (%v), want the agent's Xvfb :99 with its Xauthority", text, err)
	}

	RegisterAgentXvfb(startXvfbStandIn(t, 98), ":98", "/tmp/labtether-xauth-98.xauth")
	if _, _, err := sysconfig.PlatformClipboardRead("text"); err == nil || !strings.Contains(err.Error(), "more than one Remote View session") {
		t.Fatalf("clipboard with two sessions: %v, want the refusal in words", err)
	}
	if err := sysconfig.PlatformClipboardWriteText("x"); err == nil || !strings.Contains(err.Error(), "more than one Remote View session") {
		t.Fatalf("clipboard write with two sessions: %v, want the refusal in words", err)
	}
}
