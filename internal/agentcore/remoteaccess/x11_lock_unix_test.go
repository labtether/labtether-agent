//go:build unix

package remoteaccess

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

func useTempX11Locks(t *testing.T) {
	t.Helper()
	originalDir, originalSession, originalUsers := x11LockDir, DetectDesktopSessionFn, system.CollectUserSessionsFn
	t.Cleanup(func() {
		x11LockDir, DetectDesktopSessionFn, system.CollectUserSessionsFn = originalDir, originalSession, originalUsers
	})
	x11LockDir = t.TempDir()
	DetectDesktopSessionFn = func() DesktopSessionInfo { return DesktopSessionInfo{} }
	system.CollectUserSessionsFn = func() ([]protocol.UserSession, error) { return nil, nil }
}

func lockPath(display int) string {
	return filepath.Join(x11LockDir, fmt.Sprintf(".X%d-lock", display))
}

// The agent stops its Xvfb with SIGKILL, which leaves /tmp/.X99-lock behind.
// The next Remote View session took :99 for a live display and failed with
// "VNC server not ready" instead of starting a new Xvfb (seen live on a
// headless Linux device: the second session after any first one failed).
func TestStaleX11LockIsNotALiveDisplay(t *testing.T) {
	useTempX11Locks(t)
	exited := exec.Command("true")
	if err := exited.Run(); err != nil {
		t.Skip("no true command:", err)
	}
	for display, pid := range map[int]int{99: exited.Process.Pid, 98: os.Getpid()} {
		if err := os.WriteFile(lockPath(display), []byte(fmt.Sprintf("%10d\n", pid)), 0o444); err != nil {
			t.Fatal(err)
		}
	}
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

// /tmp is world-writable and the agent runs as root: a lock planted as a FIFO
// must not block the probe, and a link (to /dev/zero, a huge file or a
// root-only file) must not be followed. Both count as held, as any lock file
// did before, so the agent never starts its Xvfb there.
func TestPlantedX11LocksCountAsHeldWithoutBlocking(t *testing.T) {
	useTempX11Locks(t)
	if err := syscall.Mkfifo(lockPath(97), 0o666); err != nil {
		t.Skip("mkfifo:", err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockPath(96)); err != nil {
		t.Fatal(err)
	}
	done := make(chan [2]bool, 1)
	go func() { done <- [2]bool{x11LockHeld(lockPath(97)), x11LockHeld(lockPath(96))} }()
	select {
	case held := <-done:
		if !held[0] || !held[1] {
			t.Fatalf("FIFO lock held=%v, symlink lock held=%v; want both held", held[0], held[1])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a FIFO lock file blocked")
	}
	if x11LockHeld(lockPath(95)) {
		t.Fatal("a missing lock file counts as held")
	}
}
