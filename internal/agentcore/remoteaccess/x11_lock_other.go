//go:build !unix

package remoteaccess

import "os"

// x11LockHeld: X lock files are a Unix matter; anything there counts as held.
func x11LockHeld(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// x11LockOwnedBy: no Xvfb runs here, so no display is the agent's own.
func x11LockOwnedBy(string, int) bool { return false }
