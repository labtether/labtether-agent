package remoteaccess

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

var ResolveDesktopVNCMonitor = resolveDesktopVNCMonitor
var LaunchDesktopVNCMonitorReady = launchX11VNCReady
var NewVNCMonitorCommand = securityruntime.NewCommandContext

func startLinuxVNCMonitor(name string, port int, quality, password string) (*exec.Cmd, *exec.Cmd, *exec.Cmd, string, error) {
	session := DetectDesktopSessionFn()
	display := NormalizeX11DisplayIdentifier(session.Display)
	if session.Type != DesktopSessionTypeX11 || display == "" {
		return nil, nil, nil, "", fmt.Errorf("monitor %q requires an active X11 display", name)
	}
	xauthPath := DiscoverDisplayXAuthorityFn(display)
	clip, err := ResolveDesktopVNCMonitor(name, display, xauthPath)
	if err != nil {
		return nil, nil, nil, "", err
	}
	WakeX11Display(display, xauthPath)
	cmd, authPath, logTail, err := LaunchDesktopVNCMonitorReady(display, port, quality, password, xauthPath, 10*time.Second, clip)
	if err != nil {
		return nil, nil, nil, "", FormatVNCStartupError(err, logTail)
	}
	return cmd, nil, nil, authPath, nil
}

func resolveDesktopVNCMonitor(name, display, xauthPath string) (string, error) {
	if NormalizeX11DisplayIdentifier(display) == "" {
		return "", fmt.Errorf("monitor selection requires a valid X11 display")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	query := func(argument string) ([]byte, error) {
		cmd, err := NewVNCMonitorCommand(ctx, "xrandr", argument)
		if err != nil {
			return nil, err
		}
		cmd.Env = append(BuildX11ClientEnv(display, xauthPath), "LC_ALL=C")
		cmd.WaitDelay = 500 * time.Millisecond
		return securityruntime.CaptureOutput(cmd, 64*1024)
	}
	rootOutput, err := query("--current")
	if err != nil {
		return "", fmt.Errorf("resolve monitor %q root bounds: %w", name, err)
	}
	width, height, err := parseWebRTCCaptureGeometry(string(rootOutput))
	if err != nil {
		return "", err
	}
	monitors, err := query("--listmonitors")
	if err != nil {
		return "", fmt.Errorf("resolve monitor %q: %w", name, err)
	}
	return selectVNCMonitorClip(name, sysconfig.ParseXrandrMonitors(string(monitors)), width, height)
}

func selectVNCMonitorClip(name string, monitors []protocol.DisplayInfo, rootWidth, rootHeight int) (string, error) {
	var selected *protocol.DisplayInfo
	for i := range monitors {
		if monitors[i].Name == name {
			if selected != nil {
				return "", fmt.Errorf("monitor %q has ambiguous geometry", name)
			}
			selected = &monitors[i]
		}
	}
	if selected == nil {
		return "", fmt.Errorf("monitor %q is not available on the selected X11 display", name)
	}
	m := selected
	// x11vnc silently clamps or ignores invalid clips. Reject them before
	// launch so an unavailable monitor can never expose the full desktop.
	if rootWidth <= 0 || rootHeight <= 0 || m.Width <= 0 || m.Height <= 0 ||
		m.OffsetX < 0 || m.OffsetY < 0 || m.Width > rootWidth || m.Height > rootHeight ||
		m.OffsetX > rootWidth-m.Width || m.OffsetY > rootHeight-m.Height {
		return "", fmt.Errorf("monitor %q geometry is outside the X11 root screen", name)
	}
	return fmt.Sprintf("%dx%d+%d+%d", m.Width, m.Height, m.OffsetX, m.OffsetY), nil
}

func buildX11VNCArgsWithClip(display string, port int, quality, authPath, xauthPath, clip string) []string {
	args := BuildX11VNCArgs(display, port, quality, authPath, xauthPath)
	if strings.TrimSpace(clip) != "" {
		args = append(args, "-clip", clip)
	}
	return args
}
