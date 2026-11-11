//go:build !unix

package remoteaccess

import "os"

// x11LockHeld: X lock files are a Unix matter; anything there counts as held.
func x11LockHeld(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
