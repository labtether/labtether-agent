//go:build unix

package securityruntime

import (
	"os"
	"syscall"
)

// exitSignal returns the signal that ended the process, or -1.
func exitSignal(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return int(status.Signal())
	}
	return -1
}
