package files

import "io/fs"

// Windows file attribute bits, named here so the rule below can be tested on
// every platform.
const (
	winAttrHidden       = 0x2
	winAttrSystem       = 0x4
	winAttrDirectory    = 0x10
	winAttrReparsePoint = 0x400
)

// windowsListEntry returns the mode text of a Windows listing entry and
// whether the entry is hidden.
//
// Go marks a reparse point it has no file type for as irregular, which prints
// as "?". Two kinds turn up in a home folder:
//
//   - A junction. Go leaves its directory bit off, as it does for a symlink,
//     so it looked like an empty file. It is shown as a link ("L"). The
//     junctions Windows keeps for old programs (Application Data, Cookies,
//     My Documents) are hidden system entries that cannot be opened, so they
//     are hidden entries here.
//   - A cloud folder or file such as OneDrive. It opens like any other, so
//     it is shown as the folder or file it is.
func windowsListEntry(mode fs.FileMode, attrs uint32) (string, bool) {
	if mode&fs.ModeIrregular == 0 {
		return mode.String(), false
	}
	mode &^= fs.ModeIrregular
	if mode.IsDir() || attrs&winAttrDirectory == 0 || attrs&winAttrReparsePoint == 0 {
		return mode.String(), false
	}
	hidden := attrs&winAttrHidden != 0 && attrs&winAttrSystem != 0
	return (mode | fs.ModeSymlink).String(), hidden
}
