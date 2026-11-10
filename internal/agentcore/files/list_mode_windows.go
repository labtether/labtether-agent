//go:build windows

package files

import (
	"io/fs"
	"syscall"
)

// listEntryMode returns the mode text for a listing and whether the entry is
// hidden. See windowsListEntry.
func listEntryMode(info fs.FileInfo) (string, bool) {
	var attrs uint32
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok && data != nil {
		attrs = data.FileAttributes
	}
	return windowsListEntry(info.Mode(), attrs)
}
