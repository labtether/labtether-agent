//go:build !windows

package agentcore

import (
	"os"
	"syscall"
)

// keepAuthorizedKeysAccess gives the temp file the original owner and group.
// sshd's StrictModes rejects an authorized_keys owned by another user.
func keepAuthorizedKeysAccess(original os.FileInfo, _ string, tmp *os.File) error {
	want, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	current, err := tmp.Stat()
	if err != nil {
		return err
	}
	if have, ok := current.Sys().(*syscall.Stat_t); ok && have.Uid == want.Uid && have.Gid == want.Gid {
		return nil
	}
	return tmp.Chown(int(want.Uid), int(want.Gid))
}

// newAuthorizedKeysAccess needs nothing on Unix: the temp file is already 0600
// and owned by the agent's account.
func newAuthorizedKeysAccess(string, *os.File) error { return nil }

// syncAuthorizedKeysDir flushes the rename to disk. It is best effort: the
// rename has already happened and the file content was synced before it.
func syncAuthorizedKeysDir(dir string) {
	handle, err := os.Open(dir) // #nosec G304 -- Directory of the managed authorized_keys file.
	if err != nil {
		return
	}
	_ = handle.Sync()
	_ = handle.Close()
}
