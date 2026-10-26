package sysconfig

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const clipboardCommandTimeout = 5 * time.Second

var ClipboardNewCommand = securityruntime.NewCommand

func clipboardCommandOutput(env []string, name string, args ...string) ([]byte, error) {
	cmd, err := ClipboardNewCommand(name, args...)
	if err != nil {
		return nil, err
	}
	if env != nil {
		cmd.Env = env
	}
	return captureClipboardOutput(cmd, clipboardCommandTimeout)
}

func captureClipboardOutput(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	if cmd == nil || cmd.Stdout != nil {
		return nil, errors.New("clipboard command requires unset stdout")
	}
	stdout := securityruntime.NewCappedRetainingWriter(securityruntime.DefaultCommandOutputLimit)
	cmd.Stdout = stdout
	var stderr *securityruntime.CappedRetainingWriter
	if cmd.Stderr == nil {
		stderr = securityruntime.NewCappedRetainingWriter(64 * 1024)
		cmd.Stderr = stderr
	}
	err := runClipboardCommand(cmd, timeout)
	var exitErr *exec.ExitError
	if stderr != nil && errors.As(err, &exitErr) {
		exitErr.Stderr = stderr.Bytes()
	}
	if stdout.Truncated() {
		err = errors.Join(err, fmt.Errorf("%w (%d bytes)", securityruntime.ErrCommandOutputLimit, securityruntime.DefaultCommandOutputLimit))
	}
	return stdout.Bytes(), err
}

func runClipboardCommand(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || timeout <= 0 {
		return errors.New("clipboard command and positive timeout are required")
	}
	// A child may leave output or input handles with a descendant. Bound that
	// drain too; it must not hold the agent's control loop after the child exits.
	cmd.WaitDelay = 500 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return err
	}
	expired := make(chan struct{})
	watchdog := time.AfterFunc(timeout, func() {
		defer close(expired)
		// Kill only this command. A successful xclip/wl-copy parent intentionally
		// leaves a selection owner alive; never kill that owner on normal return.
		_ = cmd.Process.Kill()
	})
	err := cmd.Wait()
	if !watchdog.Stop() {
		<-expired // No delayed kill can escape this command's lifetime.
		return errors.Join(context.DeadlineExceeded, err)
	}
	return err
}
