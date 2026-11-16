//go:build unix

package securityruntime

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// commandOutputDrainTimeout bounds the wait for a finished command's output
// pipes, as on the remote command path (remoteaccess/exec_capture.go): a
// process the command started can keep them open long after it ended.
const commandOutputDrainTimeout = time.Second

// stopProcessGroupOnCancel starts cmd in its own process group. When cmd's
// context is cancelled or times out, the whole group gets SIGKILL, so a
// descendant holding the output pipe cannot keep the call waiting or stay
// behind. After the command ends, the output pipes are waited for at most
// commandOutputDrainTimeout unless the caller set its own WaitDelay. A normal
// exit leaves descendants running, as before.
//
// A command that already asks for a new session (Setsid) is its own group
// leader and is stopped the same way. A command told to join another group
// (Setpgid with a Pgid) keeps that group and is stopped as before.
func stopProcessGroupOnCancel(cmd *exec.Cmd) {
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = commandOutputDrainTimeout
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	attr := cmd.SysProcAttr
	if attr.Setpgid && attr.Pgid != 0 {
		return
	}
	if !attr.Setsid {
		attr.Setpgid = true
	}
	// exec.CommandContext sets Cancel; a command without a context has none,
	// and setting one would make Start fail.
	if cmd.Cancel == nil {
		return
	}
	cmd.Cancel = func() error {
		// A negative PID addresses the process group led by the child.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
