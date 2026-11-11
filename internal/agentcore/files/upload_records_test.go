package files

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func uploadRecordTestManager(root, stateDir string) *Manager {
	return &Manager{
		writers:         make(map[string]*PendingWrite),
		BaseDir:         root,
		HomeDir:         root,
		uploadRecordDir: filepath.Join(stateDir, uploadRecordDirName),
	}
}

func writeOldFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

// Fault: every start walked the whole shared folder (a person's home) looking
// for leftover upload files, and gave up after 20001 entries. The start
// cleanup now removes the file an earlier run recorded and nothing else. A
// walk would also have removed the unrecorded decoy.
func TestStartCleanupRemovesOnlyTheRecordedUploadLeftover(t *testing.T) {
	root, outside, stateDir := t.TempDir(), t.TempDir(), t.TempDir()

	// An earlier run: one upload finishes, one is cut off by a crash.
	earlier := uploadRecordTestManager(root, stateDir)
	chunk := base64.StdEncoding.EncodeToString([]byte("part"))
	if _, err := earlier.WriteChunk(protocol.FileWriteData{RequestID: "done", Path: "docs/done.bin", Data: chunk, Done: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := earlier.WriteChunk(protocol.FileWriteData{RequestID: "cut", Path: "docs/cut.bin", Data: chunk}); err != nil {
		t.Fatal(err)
	}
	cut := earlier.writers["cut"]
	leftover := cut.TmpPath
	_ = cut.File.Close()
	_ = cut.Root.Close()
	cut.idleTimer.Stop()

	recordDir := filepath.Join(stateDir, uploadRecordDirName)
	if ids := earlier.uploadRecordIDs(); len(ids) != 1 || uploadTempPrefix+ids[0] != filepath.Base(leftover) {
		t.Fatalf("records after one finished and one cut-off upload = %v, want only %s", ids, filepath.Base(leftover))
	}

	// Files that must survive: the same name pattern elsewhere under the
	// root with no record, a recorded temp name outside the root, and an
	// ordinary file named by a record filed under another name.
	decoy := filepath.Join(root, "other", uploadTempPrefix+strings.Repeat("a", uploadTempIDLen))
	outsideID := strings.Repeat("b", uploadTempIDLen)
	outsideFile := filepath.Join(outside, uploadTempPrefix+outsideID)
	ordinary := filepath.Join(root, "docs", "notes.txt")
	for _, path := range []string{decoy, outsideFile, ordinary} {
		writeOldFile(t, path)
	}
	planted := map[string]string{
		outsideID:                            outsideFile,
		strings.Repeat("c", uploadTempIDLen): ordinary,
	}
	for id, target := range planted {
		if err := os.WriteFile(filepath.Join(recordDir, id), []byte(target), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	restarted := uploadRecordTestManager(root, stateDir)
	restarted.removeRecordedUploadLeftovers(restarted.scope(), restarted.uploadRecordIDs())

	if _, err := os.Lstat(leftover); !os.IsNotExist(err) {
		t.Fatalf("recorded leftover %s still there (err=%v)", leftover, err)
	}
	if _, err := os.Lstat(filepath.Join(recordDir, filepath.Base(leftover)[len(uploadTempPrefix):])); !os.IsNotExist(err) {
		t.Fatalf("record of the removed leftover still there (err=%v)", err)
	}
	for _, path := range []string{decoy, outsideFile, ordinary, filepath.Join(root, "docs", "done.bin")} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}
	for id := range planted {
		if _, err := os.Lstat(filepath.Join(recordDir, id)); err != nil {
			t.Errorf("planted record %s was removed: %v", id, err)
		}
	}
}

// A state folder that cannot be written (a read-only /etc in a container)
// must not fail the upload or leave anything behind.
func TestUploadWorksWithoutAWritableStateFolder(t *testing.T) {
	root := t.TempDir()
	notAFolder := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(notAFolder, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fm := uploadRecordTestManager(root, notAFolder)
	data := base64.StdEncoding.EncodeToString([]byte("whole"))
	if _, err := fm.WriteChunk(protocol.FileWriteData{RequestID: "one", Path: "a.bin", Data: data, Done: true}); err != nil {
		t.Fatalf("upload with an unwritable state folder: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "a.bin")); err != nil || string(got) != "whole" {
		t.Fatalf("uploaded file = %q, %v", got, err)
	}
	if ids := fm.uploadRecordIDs(); len(ids) != 0 {
		t.Fatalf("records = %v, want none", ids)
	}
}
