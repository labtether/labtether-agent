package remoteaccess

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/labtether-agent/internal/x11input"
)

var NewWebRTCInternalX11Command = x11input.NewCommand

const webRTCInputCommandTimeout = 2 * time.Second

// RunWebRTCInputCommand preserves the existing backend mapping and command
// policy while bounding how long a failed input helper can hold a session.
func RunWebRTCInputCommand(name string, env []string, args ...string) error {
	return runWebRTCInputCommandContext(context.Background(), name, env, args...)
}

func runWebRTCInputCommandContext(ctx context.Context, name string, env []string, args ...string) error {
	_, err := runWebRTCInputCommandOutputContext(ctx, name, env, 4096, args...)
	return err
}

func runWebRTCInputCommandOutputContext(ctx context.Context, name string, env []string, outputLimit int, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, webRTCInputCommandTimeout)
	defer cancel()
	if err := commandCtx.Err(); err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	var err error
	if name == x11input.PolicyName {
		cmd, err = NewWebRTCInternalX11Command(args...)
	} else {
		cmd, err = NewWebRTCSecurityCommand(name, args...)
	}
	if err != nil {
		return nil, fmt.Errorf("build %s input command: %w", name, err)
	}
	cmd.Env = env
	output := securityruntime.NewCappedRetainingWriter(outputLimit)
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s input command: %w", name, err)
	}
	stopCancel := context.AfterFunc(commandCtx, func() { _ = cmd.Process.Kill() })
	defer stopCancel()
	runErr := cmd.Wait()
	if err := commandCtx.Err(); err != nil {
		return nil, fmt.Errorf("run %s input command: %w", name, err)
	}
	if output.Truncated() {
		return nil, fmt.Errorf("%s output exceeded %d bytes", name, outputLimit)
	}
	if runErr == nil {
		return output.Bytes(), nil
	}
	detail := TruncateCommandOutput(output.Bytes(), 1024)
	if detail != "" {
		return nil, fmt.Errorf("run %s input command: %w: %s", name, runErr, detail)
	}
	return nil, fmt.Errorf("run %s input command: %w", name, runErr)
}
