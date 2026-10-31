package remoteaccess

import (
	"slices"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

// The Hub's systemd unit sets PrivateTmp, which hides /tmp/.X*-lock. The
// display scan then ran loginctl and who once per display, 100 times, and
// desktop diagnose missed the Hub's 15 s wait (504 every time).
func TestDisplayScanLooksUpSessionsOnce(t *testing.T) {
	originalSession, originalUsers := DetectDesktopSessionFn, system.CollectUserSessionsFn
	t.Cleanup(func() {
		DetectDesktopSessionFn, system.CollectUserSessionsFn = originalSession, originalUsers
	})
	sessionCalls, userCalls := 0, 0
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		sessionCalls++
		return DesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":7"}
	}
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) {
		userCalls++
		return []protocol.UserSession{{Username: "demo", Terminal: "pts/1", RemoteHost: ":12"}}, nil
	}

	displays := AppendDetectedActiveDisplays(nil)

	if sessionCalls > 1 || userCalls > 1 {
		t.Fatalf("scan ran loginctl %d times and who %d times, want at most once each", sessionCalls, userCalls)
	}
	if !slices.Contains(displays, ":7") || !slices.Contains(displays, ":12") {
		t.Fatalf("displays = %v, want the session display :7 and the login display :12", displays)
	}
}
