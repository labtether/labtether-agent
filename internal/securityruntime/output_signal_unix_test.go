//go:build unix

package securityruntime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// exitSignal returns the signal that ended the process, or -1.
func exitSignal(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return int(status.Signal())
	}
	return -1
}

// processStillRunning reports whether pid still runs, checked for up to 1 s
// so an ended process can be reaped. A zombie counts as ended (Linux reads
// its state from /proc; elsewhere a signal-0 probe decides).
func processStillRunning(pid int) bool {
	for range 20 {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		switch {
		case err == nil:
			if index := bytes.LastIndex(stat, []byte(") ")); index >= 0 && bytes.HasPrefix(stat[index+2:], []byte("Z")) {
				return false
			}
		case errors.Is(err, os.ErrNotExist) && syscall.Kill(pid, 0) != nil:
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

// killStrayProcess removes a process a failing case left behind.
func killStrayProcess(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
