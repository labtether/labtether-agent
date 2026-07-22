//go:build linux

package agentcore

import (
	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
)

func init() {
	// Wire clipboard's desktop session detector so xclip/xsel can find the
	// correct DISPLAY and XAUTHORITY for the active graphical session.
	// Without this, clipboard operations fall back to DISPLAY=:0 which may
	// not match the actual active display.
	sysconfig.DetectLinuxDesktopSessionFn = func() sysconfig.LinuxDesktopSessionInfo {
		session := detectDesktopSessionFn()
		return sysconfig.LinuxDesktopSessionInfo{
			Type:           session.Type,
			Display:        session.Display,
			WaylandDisplay: session.WaylandDisplay,
			XDGRuntimeDir:  session.XDGRuntimeDir,
		}
	}

	// Display enumeration lives in sysconfig to avoid a package cycle, while
	// desktop-session and X11-auth discovery live in remoteaccess. Wire those
	// hooks here so xrandr targets the detected session with its real
	// XAUTHORITY instead of falling back to an unauthenticated DISPLAY=:0.
	sysconfig.DetectDesktopSessionTypeFn = func() string {
		return detectDesktopSessionFn().Type
	}
	sysconfig.PreferredX11DisplayFn = preferredX11Display
	sysconfig.WakeX11DisplayFn = wakeX11Display
	sysconfig.BuildX11ClientEnvFn = buildX11ClientEnv
}
