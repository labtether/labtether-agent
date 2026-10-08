package files

import (
	"github.com/labtether/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleFileDeleteRemovesSymlinkWithoutTouchingTarget(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(baseDir, "outside-link")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	transport := &testFileTransport{}
	fm.HandleFileDelete(transport, protocol.Message{
		Type: protocol.MsgFileDelete,
		ID:   "delete-1",
		Data: marshalTestMessage(t, protocol.FileDeleteData{
			RequestID: "delete-1",
			Path:      "outside-link",
		}),
	})

	result := lastFileResult(t, transport)
	if !result.OK {
		t.Fatalf("expected symlink delete to succeed, got error: %s", result.Error)
	}
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("expected symlink to be removed, stat err=%v", err)
	}
	got, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatalf("outside target was removed or unreadable: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("outside target content changed: %q", string(got))
	}
}

func TestHandleFileRenameRejectsBaseDirectory(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	transport := &testFileTransport{}
	fm.HandleFileRename(transport, protocol.Message{
		Type: protocol.MsgFileRename,
		ID:   "rename-base",
		Data: marshalTestMessage(t, protocol.FileRenameData{
			RequestID: "rename-base",
			OldPath:   "",
			NewPath:   "renamed-base",
		}),
	})

	result := lastFileResult(t, transport)
	if result.OK {
		t.Fatal("expected base directory rename to fail")
	}
	if !strings.Contains(result.Error, "base directory") {
		t.Fatalf("expected base directory error, got %q", result.Error)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "keep.txt")); err != nil {
		t.Fatalf("expected base directory contents to remain available: %v", err)
	}
}

func TestHandleFileRenameRejectsExistingDestination(t *testing.T) {
	baseDir := t.TempDir()
	srcPath := filepath.Join(baseDir, "source.txt")
	dstPath := filepath.Join(baseDir, "dest.txt")
	if err := os.WriteFile(srcPath, []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, []byte("dest"), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	transport := &testFileTransport{}
	fm.HandleFileRename(transport, protocol.Message{
		Type: protocol.MsgFileRename,
		ID:   "rename-existing-dest",
		Data: marshalTestMessage(t, protocol.FileRenameData{
			RequestID: "rename-existing-dest",
			OldPath:   "source.txt",
			NewPath:   "dest.txt",
		}),
	})

	result := lastFileResult(t, transport)
	if result.OK {
		t.Fatal("expected rename over existing destination to fail")
	}
	if !strings.Contains(result.Error, "destination already exists") {
		t.Fatalf("expected existing destination error, got %q", result.Error)
	}
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("expected source file to remain: %v", err)
	}
	if string(srcBytes) != "source" {
		t.Fatalf("unexpected source content: %q", string(srcBytes))
	}
	dstBytes, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("expected destination file to remain: %v", err)
	}
	if string(dstBytes) != "dest" {
		t.Fatalf("unexpected destination content: %q", string(dstBytes))
	}
}

func TestCopyPathRecursiveCopiesNestedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "child.txt"), []byte("child-content"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := CopyPathRecursive(srcDir, dstDir); err != nil {
		t.Fatalf("CopyPathRecursive failed: %v", err)
	}

	rootBytes, err := os.ReadFile(filepath.Join(dstDir, "root.txt"))
	if err != nil {
		t.Fatalf("read copied root file: %v", err)
	}
	if string(rootBytes) != "root-content" {
		t.Fatalf("unexpected root file content: %q", string(rootBytes))
	}

	childBytes, err := os.ReadFile(filepath.Join(dstDir, "sub", "child.txt"))
	if err != nil {
		t.Fatalf("read copied child file: %v", err)
	}
	if string(childBytes) != "child-content" {
		t.Fatalf("unexpected child file content: %q", string(childBytes))
	}
}

func TestCopyPathRecursiveRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(targetFile, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	err := CopyPathRecursive(linkPath, filepath.Join(tmpDir, "copied-link.txt"))
	if err == nil {
		t.Fatal("expected symlink copy to fail")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got: %v", err)
	}
}

func TestCopyPathRecursiveRejectsDestinationInsideSource(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(srcDir, "nested-copy")
	err := CopyPathRecursive(srcDir, dstDir)
	if err == nil {
		t.Fatal("expected nested destination copy to fail")
	}
	if !strings.Contains(err.Error(), "inside source directory") {
		t.Fatalf("expected inside-source error, got: %v", err)
	}
}

func TestCopyPathRecursiveRejectsDestinationInsideSourceThroughSymlinkedParent(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(tmpDir, "link-to-src")
	if err := os.Symlink(srcDir, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	dstDir := filepath.Join(linkPath, "nested-copy")
	err := CopyPathRecursive(srcDir, dstDir)
	if err == nil {
		t.Fatal("expected symlink-parent nested destination copy to fail")
	}
	if !strings.Contains(err.Error(), "inside source directory") {
		t.Fatalf("expected inside-source error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(srcDir, "nested-copy")); !os.IsNotExist(statErr) {
		t.Fatalf("expected nested copy directory to remain absent, stat err=%v", statErr)
	}
}
