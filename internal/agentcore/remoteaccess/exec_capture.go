package remoteaccess

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const remoteCommandOutputDrainTimeout = time.Second

// A successful direct child can leave a descendant holding its output pipes.
// Bound the drain after child exit or cancellation so the handler always gives
// up its slot. Cancellation and timeout also stop the command's process group
// where the platform has one; a normal exit leaves descendants running.
// cmd must come from exec.CommandContext so the cancel hook is permitted.
func runRemoteCommandOutput(cmd *exec.Cmd) (string, error) {
	cmd.WaitDelay = remoteCommandOutputDrainTimeout
	killProcessGroupOnCancel(cmd)
	output := securityruntime.NewCappedRetainingWriter(MaxCommandOutputBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = fmt.Errorf("%s: %w", heldOutputNote, err)
	}
	return retainedCommandOutput(output), err
}

const heldOutputNote = "command output did not close after process exit; descendant processes may still be running"

// remoteCommandOutcome turns a finished remote command into its wire status,
// output and exit code. The output keeps only what the command printed, plus
// one agent note when it did not end normally; Go error text such as
// "exit status 2" never goes in. exitCode is set whenever the process exited
// on its own, including 0. It stays nil when the command could not start,
// timed out, was canceled or was stopped by a signal, because no real exit
// status exists then (Windows reports a killed process as exit code 1).
func remoteCommandOutcome(ctx context.Context, cmd *exec.Cmd, output string, runErr error) (status, text string, exitCode *int) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return "failed", withAgentNote(output, "command timed out"), nil
		}
		return "failed", withAgentNote(output, "command canceled"), nil
	}
	state := cmd.ProcessState
	if state == nil {
		reason := "command could not start"
		if cmd.Process != nil {
			reason = "command exit status unknown"
		}
		if runErr != nil {
			reason += ": " + runErr.Error()
		}
		return "failed", withAgentNote(output, reason), nil
	}
	if !state.Exited() {
		return "failed", withAgentNote(output, "command stopped by "+state.String()), nil
	}
	code := state.ExitCode()
	switch {
	case code != 0:
		return "failed", output, &code
	case errors.Is(runErr, exec.ErrWaitDelay):
		return "failed", withAgentNote(output, heldOutputNote), &code
	case runErr != nil:
		return "failed", withAgentNote(output, "command output incomplete: "+runErr.Error()), &code
	}
	return "succeeded", output, &code
}

func withAgentNote(output, note string) string {
	if output == "" {
		return note
	}
	return output + "\nerror: " + note
}
