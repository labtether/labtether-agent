//go:build !windows

package docker

import (
	"os"
	"syscall"
)

// composeDirIsPrivate requires the agent's own account and no group or other
// write access, so no other local user can swap files after validation.
func composeDirIsPrivate(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid()) && info.Mode().Perm()&0o022 == 0
}
