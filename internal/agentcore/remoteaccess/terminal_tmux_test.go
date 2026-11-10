//go:build !windows

package remoteaccess

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// The terminal in the console showed tmux's status bar with an internal
// session name, and its shell opened in the agent's folder. This runs the real
// start line against a private tmux server and checks both, for a new session
// and for one that already exists with the bar on.
func TestTmuxStartHidesStatusLineAndOpensInStartDir(t *testing.T) {
	tmuxPath, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux is not installed")
	}
	// A short socket folder: unix socket paths have a small length limit.
	sockDir, err := os.MkdirTemp("/tmp", "lt-tmux-")
	if err != nil {
		t.Fatal(err)
	}
	startDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"TMUX_TMPDIR=" + sockDir, "TERM=xterm-256color", "PATH=" + os.Getenv("PATH"), "HOME=" + startDir, "SHELL=/bin/sh"}
	tmux := func(args ...string) string {
		cmd := exec.Command(tmuxPath, args...)
		cmd.Env = env
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	t.Cleanup(func() {
		tmux("kill-server")
		_ = os.RemoveAll(sockDir)
	})

	const session = "lt-test"
	attach := func() {
		t.Helper()
		cmd := exec.Command(tmuxPath, tmuxStartArgs(session, startDir)...)
		cmd.Env = env
		ptmx, startErr := pty.StartWithSize(cmd, &pty.Winsize{Cols: 100, Rows: 30})
		if startErr != nil {
			t.Fatalf("start tmux: %v", startErr)
		}
		deadline := time.Now().Add(10 * time.Second)
		for tmux("show-options", "-t", session, "status") != "status off" {
			if time.Now().After(deadline) {
				t.Fatalf("status line still shown: %q", tmux("show-options", "-t", session, "status"))
			}
			time.Sleep(50 * time.Millisecond)
		}
		// Closing the client detaches; the session stays, as it does when a connection drops.
		_ = ptmx.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}

	attach()
	if got := tmux("display-message", "-p", "-t", session, "#{session_path}"); got != startDir {
		t.Fatalf("new session opened in %q, want %q", got, startDir)
	}

	tmux("set-option", "-t", session, "status", "on")
	tmux("new-session", "-d", "-s", "someone-elses")
	attach()
	if got := tmux("show-options", "-t", "someone-elses", "status"); got != "" {
		t.Fatalf("another session's status line was changed: %q", got)
	}
}
