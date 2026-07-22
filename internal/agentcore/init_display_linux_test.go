//go:build linux

package agentcore

import (
	"strings"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/remoteaccess"
	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
)

func TestLinuxDisplayHooksUseDetectedSessionAndXAuthority(t *testing.T) {
	originalAgentDetect := detectDesktopSessionFn
	originalRemoteDetect := remoteaccess.DetectDesktopSessionFn
	originalDiscoverXAuthority := remoteaccess.DiscoverDisplayXAuthorityFn
	t.Cleanup(func() {
		detectDesktopSessionFn = originalAgentDetect
		remoteaccess.DetectDesktopSessionFn = originalRemoteDetect
		remoteaccess.DiscoverDisplayXAuthorityFn = originalDiscoverXAuthority
	})

	if sysconfig.DetectDesktopSessionTypeFn == nil ||
		sysconfig.PreferredX11DisplayFn == nil ||
		sysconfig.WakeX11DisplayFn == nil ||
		sysconfig.BuildX11ClientEnvFn == nil {
		t.Fatal("Linux display hooks are not fully wired")
	}

	session := desktopSessionInfo{Type: desktopSessionTypeX11, Display: ":7"}
	detectDesktopSessionFn = func() desktopSessionInfo { return session }
	remoteaccess.DetectDesktopSessionFn = func() remoteaccess.DesktopSessionInfo {
		return remoteaccess.DesktopSessionInfo{Type: remoteaccess.DesktopSessionTypeX11, Display: ":7"}
	}
	remoteaccess.DiscoverDisplayXAuthorityFn = func(display string) string {
		if display != ":7" {
			t.Fatalf("display=%q, want :7", display)
		}
		return "/run/lightdm/root/:7"
	}

	if got := sysconfig.DetectDesktopSessionTypeFn(); got != desktopSessionTypeX11 {
		t.Fatalf("session type=%q, want %q", got, desktopSessionTypeX11)
	}
	if got := sysconfig.PreferredX11DisplayFn(); got != ":7" {
		t.Fatalf("preferred display=%q, want :7", got)
	}
	env := sysconfig.BuildX11ClientEnvFn(":7", "")
	if !containsDisplayEnv(env, "DISPLAY=:7") {
		t.Fatalf("DISPLAY missing from X11 client env: %v", env)
	}
	if !containsDisplayEnv(env, "XAUTHORITY=/run/lightdm/root/:7") {
		t.Fatalf("XAUTHORITY missing from X11 client env: %v", env)
	}
}

func containsDisplayEnv(env []string, want string) bool {
	for _, entry := range env {
		if strings.TrimSpace(entry) == want {
			return true
		}
	}
	return false
}
