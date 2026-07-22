//go:build unix

package files

import (
	"os"
	"syscall"
)

// openRootFileForRead opens without waiting for a FIFO peer. The caller then
// validates the opened descriptor with Stat, avoiding both FIFO-open blocking
// and a path precheck/open TOCTOU window.
func openRootFileForRead(root *os.Root, relPath string) (*os.File, error) {
	return root.OpenFile(relPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
