package files

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// windowsDirMaker answers like Windows at a drive root: mkdir on the root or
// on a folder that exists fails with "Access is denied".
type windowsDirMaker struct {
	existing map[string]bool
	made     []string
}

func (w *windowsDirMaker) Stat(name string) (os.FileInfo, error) {
	if w.existing[name] {
		return dirInfo(name), nil
	}
	return nil, fs.ErrNotExist
}

func (w *windowsDirMaker) MkdirAll(name string, _ os.FileMode) error {
	if name == "." || w.existing[name] {
		return &os.PathError{Op: "mkdirat", Path: name, Err: errors.New("Access is denied.")}
	}
	w.made = append(w.made, name)
	return nil
}

// Risk: uploading or copying to C:\x failed on Windows because the agent
// called MkdirAll on the parent, the drive root itself.
func TestMkdirIfMissingSkipsDriveRootAndExistingParent(t *testing.T) {
	root := &windowsDirMaker{existing: map[string]bool{"Users": true}}
	for _, target := range []string{"report.txt", filepath.Join("Users", "report.txt")} {
		if err := mkdirIfMissing(root, filepath.Dir(target), 0o750); err != nil {
			t.Fatalf("parent of %q: %v", target, err)
		}
	}
	if len(root.made) != 0 {
		t.Fatalf("created %v, want nothing", root.made)
	}
	missing := filepath.Join("Users", "new", "report.txt")
	if err := mkdirIfMissing(root, filepath.Dir(missing), 0o750); err != nil || len(root.made) != 1 {
		t.Fatalf("missing parent: err=%v made=%v", err, root.made)
	}
}

type dirInfo string

func (d dirInfo) Name() string       { return filepath.Base(string(d)) }
func (d dirInfo) Size() int64        { return 0 }
func (d dirInfo) Mode() os.FileMode  { return os.ModeDir | 0o755 }
func (d dirInfo) ModTime() time.Time { return time.Time{} }
func (d dirInfo) IsDir() bool        { return true }
func (d dirInfo) Sys() any           { return nil }
