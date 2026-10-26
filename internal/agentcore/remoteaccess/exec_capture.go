package remoteaccess

import (
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const remoteCommandOutputDrainTimeout = time.Second

// A successful direct child can leave a descendant holding its output pipes.
// Bound the drain after child exit or cancellation so the handler always gives
// up its slot. This does not kill or claim ownership of descendant processes.
func runRemoteCommandOutput(cmd *exec.Cmd) (string, error) {
	cmd.WaitDelay = remoteCommandOutputDrainTimeout
	output := securityruntime.NewCappedRetainingWriter(MaxCommandOutputBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = fmt.Errorf("command output did not close after process exit; descendant processes may still be running: %w", err)
	}
	return retainedCommandOutput(output), err
}
