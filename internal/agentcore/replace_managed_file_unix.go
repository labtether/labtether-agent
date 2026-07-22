//go:build !windows

package agentcore

import "os"

func replaceManagedFile(source, destination string) error {
	return os.Rename(source, destination)
}
