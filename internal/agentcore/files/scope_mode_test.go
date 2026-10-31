package files

import (
	"path/filepath"
	"testing"
)

// Switching from full to home while the agent runs must narrow access at once.
func TestSetRootModeNarrowsAccessWhileRunning(t *testing.T) {
	home := t.TempDir()
	originalHome := FileUserHomeDirFn
	FileUserHomeDirFn = func() (string, error) { return home, nil }
	t.Cleanup(func() { FileUserHomeDirFn = originalHome })

	fm := &Manager{writers: make(map[string]*PendingWrite), BaseDir: FilesystemRootForPath(home), HomeDir: home, rootMode: "full"}
	outsideHome := filepath.Dir(home)
	if root, _, _, err := fm.OpenRootPath(outsideHome); err != nil {
		t.Fatalf("full mode refused %s: %v", outsideHome, err)
	} else {
		_ = root.Close()
	}

	fm.SetRootMode("home")

	if _, _, _, err := fm.OpenRootPath(outsideHome); err == nil {
		t.Fatalf("home mode still allowed %s", outsideHome)
	}
	if root, _, _, err := fm.OpenRootPath("~"); err != nil {
		t.Fatalf("home mode refused the home folder: %v", err)
	} else {
		_ = root.Close()
	}
}
