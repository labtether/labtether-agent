//go:build unix

package remoteaccess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// isolateAgentXvfbs gives a test its own lock directory and an empty record.
func isolateAgentXvfbs(t *testing.T) string {
	t.Helper()
	originalDir := x11LockDir
	x11LockDir = t.TempDir()
	agentXvfbs.mu.Lock()
	saved := agentXvfbs.entries
	agentXvfbs.entries = nil
	agentXvfbs.mu.Unlock()
	t.Cleanup(func() {
		x11LockDir = originalDir
		agentXvfbs.mu.Lock()
		agentXvfbs.entries = saved
		agentXvfbs.mu.Unlock()
	})
	return x11LockDir
}

// startXvfbStandIn runs a process in place of Xvfb and writes the display's
// lock file with its PID, as Xvfb does.
func startXvfbStandIn(t *testing.T, display int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stand-in: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	writeX11Lock(t, display, cmd.Process.Pid)
	return cmd
}

func writeX11Lock(t *testing.T, display, pid int) {
	t.Helper()
	path := filepath.Join(x11LockDir, fmt.Sprintf(".X%d-lock", display))
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%10d\n", pid)), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
}

// An Xvfb that crashed (or was killed) stays recorded until someone notices.
// Another local user could then start their own server on the same number,
// without the agent's cookie, and get the viewer's clipboard. An exited
// Xvfb, or one whose lock names another process, is never returned.
func TestAgentXvfbDisplayDropsAnXvfbThatExited(t *testing.T) {
	isolateAgentXvfbs(t)
	xvfb := startXvfbStandIn(t, 99)
	RegisterAgentXvfb(xvfb, ":99", "/tmp/labtether-xauth-99.xauth")
	if display, xauth, err := AgentXvfbDisplay(); err != nil || display != ":99" || xauth != "/tmp/labtether-xauth-99.xauth" {
		t.Fatalf("live agent Xvfb = %q %q %v, want :99 with its xauth", display, xauth, err)
	}

	_ = xvfb.Process.Kill()
	_ = xvfb.Wait()
	other := startXvfbStandIn(t, 99) // someone else's server on :99 after the crash
	if display, _, err := AgentXvfbDisplay(); err != nil || display != "" {
		t.Fatalf("after the agent's Xvfb exited = %q %v, want none", display, err)
	}

	stillRunning := startXvfbStandIn(t, 98)
	writeX11Lock(t, 98, other.Process.Pid) // the lock now names another process
	RegisterAgentXvfb(stillRunning, ":98", "/tmp/labtether-xauth-98.xauth")
	if display, _, err := AgentXvfbDisplay(); err != nil || display != "" {
		t.Fatalf("agent Xvfb whose lock names another process = %q %v, want none", display, err)
	}
}

// The clipboard request does not say which Remote View session it is for, so
// with two of the agent's Xvfbs running it is refused in words instead of
// reaching another viewer's display.
func TestAgentXvfbDisplayRefusesWhileTwoSessionsRun(t *testing.T) {
	isolateAgentXvfbs(t)
	first := startXvfbStandIn(t, 99)
	second := startXvfbStandIn(t, 98)
	RegisterAgentXvfb(first, ":99", "/tmp/labtether-xauth-99.xauth")
	RegisterAgentXvfb(second, ":98", "/tmp/labtether-xauth-98.xauth")
	if display, _, err := AgentXvfbDisplay(); !errors.Is(err, ErrSeveralAgentXvfbs) || display != "" {
		t.Fatalf("two agent Xvfbs = %q %v, want the refusal", display, err)
	}
	ForgetAgentXvfb(second)
	if display, _, err := AgentXvfbDisplay(); err != nil || display != ":99" {
		t.Fatalf("one agent Xvfb left = %q %v, want :99", display, err)
	}
}
