//go:build !unix

package remoteaccess

// processAlive cannot be checked here; X lock files are a Unix matter.
func processAlive(int) bool { return true }
