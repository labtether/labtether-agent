//go:build windows

package files

import "golang.org/x/sys/windows"

// fixedDriveRoots lists the root of every fixed local drive, such as C:\ and
// D:\. Removable, network and optical drives are left out.
func fixedDriveRoots() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var roots []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		path, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		if windows.GetDriveType(path) == windows.DRIVE_FIXED {
			roots = append(roots, root)
		}
	}
	return roots
}
