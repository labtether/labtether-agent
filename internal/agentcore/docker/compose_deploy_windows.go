//go:build windows

package docker

import "os"

// Windows reports no POSIX owner or mode bits here. The managed root lives in
// the agent account's temporary directory, whose ACL already excludes others.
func composeDirIsPrivate(os.FileInfo) bool { return true }
