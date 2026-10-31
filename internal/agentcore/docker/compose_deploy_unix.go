//go:build !windows

package docker

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// defaultComposeStacksRoot is a persistent, root-owned state folder for a root
// agent (/var/lib/labtether/stacks, or /var/db on FreeBSD). Other accounts use
// their own configuration folder.
func defaultComposeStacksRoot() string {
	if os.Geteuid() == 0 && runtime.GOOS != "darwin" {
		if runtime.GOOS == "freebsd" {
			return "/var/db/labtether/stacks"
		}
		return "/var/lib/labtether/stacks"
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "labtether", "stacks")
	}
	return filepath.Join(os.TempDir(), "labtether-stacks")
}

// composeDirIsPrivate requires the agent's own account and no group or other
// write access, so no other local user can swap files after validation.
func composeDirIsPrivate(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid()) && info.Mode().Perm()&0o022 == 0
}
