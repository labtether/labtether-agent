package remoteaccess

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// The agent stops its Xvfb with SIGKILL, which leaves /tmp/.X99-lock behind.
// The next Remote View session took :99 for a live display and failed with
// "VNC server not ready" instead of starting a new Xvfb (seen live on a
// headless Linux device: the second session after any first one failed).
func TestStaleX11LockIsNotALiveDisplay(t *testing.T) {
	originalDir, originalSession, originalUsers := x11LockDir, DetectDesktopSessionFn, system.CollectUserSessionsFn
	t.Cleanup(func() { x11LockDir, DetectDesktopSessionFn, system.CollectUserSessionsFn = originalDir, originalSession, originalUsers })
	x11LockDir = t.TempDir()
	DetectDesktopSessionFn = func() DesktopSessionInfo { return DesktopSessionInfo{} }
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }

	exited := exec.Command("true")
	if err := exited.Run(); err != nil {
		t.Skip("no true command:", err)
	}
	writeLock := func(display, pid int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(x11LockDir, fmt.Sprintf(".X%d-lock", display)), []byte(fmt.Sprintf("%10d\n", pid)), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	writeLock(99, exited.Process.Pid)
	writeLock(98, os.Getpid())

	if IsDisplayAvailable(":99") {
		t.Fatal(":99 has only a stale lock but counts as a live display")
	}
	if !IsDisplayAvailable(":98") {
		t.Fatal(":98 has the lock of a running process but counts as not available")
	}
	if got := FindFreeDisplay(); got != 99 {
		t.Fatalf("FindFreeDisplay = %d, want 99 (its lock is stale)", got)
	}
}
