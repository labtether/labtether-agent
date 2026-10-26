//go:build unix

package remoteaccess

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const remoteCommandKillsProcessGroup = true

// Start remote commands in their own process group. Cancellation or timeout
// then stops the whole group, including descendants that inherited the output
// pipes, instead of only the direct child.
func killProcessGroupOnCancel(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		// A negative PID addresses the process group led by the child.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
