package agentcore

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadBoundedRegularFileRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), 17), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(large, 16); err == nil {
		t.Fatal("oversized managed file was accepted")
	}

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires optional Windows privileges")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(large, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(link, 64); err == nil {
		t.Fatal("symlinked managed file was accepted")
	}
}

func TestWriteManagedFileAtomicReplacesSymlinkWithoutFollowing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires optional Windows privileges")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(target, []byte("do-not-change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedFileAtomic(path, []byte("replacement"), 0o600, true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "do-not-change" {
		t.Fatalf("symlink target changed: content=%q err=%v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("replacement mode=%v, want regular", info.Mode())
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement content=%q err=%v", got, err)
	}
}
