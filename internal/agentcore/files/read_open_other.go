//go:build !unix && !windows

package files

import "os"

func openRootFileForRead(root *os.Root, relPath string) (*os.File, error) {
	return root.OpenFile(relPath, os.O_RDONLY, 0)
}
