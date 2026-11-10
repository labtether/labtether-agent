//go:build !windows

package remoteaccess

import (
	"context"
	"os/exec"
)

// Only Windows has a native terminal besides the PTY; other systems that lack
// a PTY get the pipe bridge.
func startNativeTerminal(_ context.Context, cmd *exec.Cmd, _, _ uint16) (*nativeTerminal, error) {
	return startPipeTerminal(cmd)
}
