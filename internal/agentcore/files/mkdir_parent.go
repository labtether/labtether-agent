package files

import "os"

// dirMaker is the part of *os.Root that mkdirIfMissing uses.
type dirMaker interface {
	Stat(name string) (os.FileInfo, error)
	MkdirAll(name string, perm os.FileMode) error
}

// mkdirIfMissing creates dir inside root unless it is the root's own folder
// (".") or already a directory. Windows answers mkdir on a drive root such as
// C:\ with "Access is denied" instead of "already exists", so calling
// os.Root.MkdirAll there failed every upload and copy into a drive root.
func mkdirIfMissing(root dirMaker, dir string, perm os.FileMode) error {
	if dir == "" || dir == "." {
		return nil
	}
	if info, err := root.Stat(dir); err == nil && info.IsDir() {
		return nil
	}
	return root.MkdirAll(dir, perm)
}
