//go:build !windows

package files

import "io/fs"

// listEntryMode returns the mode text for a listing and whether the entry is
// hidden. Only Windows has entries that need more than the mode itself.
func listEntryMode(info fs.FileInfo) (string, bool) {
	return info.Mode().String(), false
}
