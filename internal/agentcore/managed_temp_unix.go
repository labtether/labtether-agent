//go:build !windows

package agentcore

import "os"

// createManagedTemp creates the staging file for an atomic write. os.CreateTemp
// already creates it with mode 0600, so no other account can read it on Unix.
func createManagedTemp(dir string, _ bool) (*os.File, error) {
	return os.CreateTemp(dir, managedTempPattern)
}
