//go:build linux

package sysconfig

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// DesktopSessionType and DesktopSessionDetector are injectable hooks for
// desktop session detection that lives in the remoteaccess subpackage (or
// still in root during incremental extraction). The parent agentcore package
// wires these at init time.
var (
	DetectDesktopSessionTypeFn func() string                   // returns session type string
	PreferredX11DisplayFn      func() string                   // returns preferred X11 DISPLAY value
	WakeX11DisplayFn           func(display, xauthPath string) // wakes the display
	BuildX11ClientEnvFn        func(display, xauthPath string) []string
	NewDisplayListCommand      = securityruntime.NewCommandContext
)

// DesktopSessionTypeWayland is the session type constant for Wayland sessions.
const DesktopSessionTypeWayland = "wayland"

const DesktopSessionTypeX11 = "x11"

func PlatformListDisplays() ([]protocol.DisplayInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if DetectDesktopSessionTypeFn == nil {
		log.Printf("display: desktop session detection unavailable; returning no displays")
		return nil, nil
	}
	sessionType := strings.ToLower(strings.TrimSpace(DetectDesktopSessionTypeFn()))
	if sessionType == DesktopSessionTypeWayland {
		log.Printf("display: skipping xrandr monitor enumeration for Wayland desktop backend")
		return nil, nil
	}
	if sessionType != DesktopSessionTypeX11 {
		log.Printf("display: no active X11 desktop session; returning no displays")
		return nil, nil
	}

	if PreferredX11DisplayFn == nil {
		log.Printf("display: preferred X11 display detection unavailable; returning no displays")
		return nil, nil
	}
	display := strings.TrimSpace(PreferredX11DisplayFn())
	if display == "" {
		log.Printf("display: active X11 session has no usable display; returning no displays")
		return nil, nil
	}
	if WakeX11DisplayFn != nil {
		WakeX11DisplayFn(display, "")
	}

	cmd, err := NewDisplayListCommand(ctx, "xrandr", "--listmonitors")
	if err != nil {
		log.Printf("display: failed to build xrandr command for %s: %v", display, err)
		return nil, err
	}
	if BuildX11ClientEnvFn == nil {
		log.Printf("display: X11 client environment builder unavailable for %s", display)
		return nil, nil
	}
	cmd.Env = BuildX11ClientEnvFn(display, "")
	out, err := securityruntime.CaptureCombinedOutput(cmd, securityruntime.DefaultCommandOutputLimit)
	if err != nil {
		log.Printf("display: xrandr --listmonitors failed on %s: %v (%s)", display, err, strings.TrimSpace(string(out)))
		return nil, err
	}
	return ParseXrandrMonitors(string(out)), nil
}
