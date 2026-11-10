package files

import (
	"io/fs"
	"strings"
	"testing"
)

// Fault: a Windows home listing showed junctions as empty files with mode
// "?rw-rw-rw-" and a OneDrive folder as "d?r-xr-xr-x".
func TestWindowsListEntryModes(t *testing.T) {
	const archive, notIndexed, readOnly = 0x20, 0x2000, 0x1
	cases := []struct {
		name       string
		mode       fs.FileMode
		attrs      uint32
		wantMode   string
		wantHidden bool
	}{
		{"file", 0o666, archive, "-rw-rw-rw-", false},
		{"folder", fs.ModeDir | 0o777, winAttrDirectory, "drwxrwxrwx", false},
		{"symlink", fs.ModeSymlink | 0o666, winAttrReparsePoint, "Lrw-rw-rw-", false},
		{"junction Windows keeps for old programs", fs.ModeIrregular | 0o666,
			winAttrHidden | winAttrSystem | winAttrDirectory | winAttrReparsePoint | notIndexed, "Lrw-rw-rw-", true},
		{"junction a person made", fs.ModeIrregular | 0o666, winAttrDirectory | winAttrReparsePoint, "Lrw-rw-rw-", false},
		{"OneDrive folder", fs.ModeDir | fs.ModeIrregular | 0o555,
			readOnly | winAttrDirectory | winAttrReparsePoint, "dr-xr-xr-x", false},
		{"cloud file not yet downloaded", fs.ModeIrregular | 0o666, archive | winAttrReparsePoint, "-rw-rw-rw-", false},
		{"hidden system folder that opens", fs.ModeDir | 0o777,
			winAttrHidden | winAttrSystem | winAttrDirectory, "drwxrwxrwx", false},
	}
	for _, tc := range cases {
		gotMode, gotHidden := windowsListEntry(tc.mode, tc.attrs)
		if gotMode != tc.wantMode || gotHidden != tc.wantHidden {
			t.Errorf("%s: got %q hidden=%v, want %q hidden=%v", tc.name, gotMode, gotHidden, tc.wantMode, tc.wantHidden)
		}
		if strings.Contains(gotMode, "?") {
			t.Errorf("%s: mode %q holds a question mark", tc.name, gotMode)
		}
	}
}
