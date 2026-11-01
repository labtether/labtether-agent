//go:build windows

package docker

import (
	"os"
	"path/filepath"
)

// defaultComposeStacksRoot keeps the existing location on Windows: the agent
// account's temporary directory.
func defaultComposeStacksRoot() string { return filepath.Join(os.TempDir(), "labtether-stacks") }

// Windows reports no POSIX owner or mode bits here. The managed root lives in
// the agent account's temporary directory, whose ACL already excludes others.
func composeDirIsPrivate(os.FileInfo) bool { return true }
