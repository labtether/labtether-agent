package agentcore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// errorPrivilegeNotHeld is ERROR_PRIVILEGE_NOT_HELD, the error Windows gives
// an account that may not create symbolic links.
const errorPrivilegeNotHeld = syscall.Errno(1314)

// makeTestSymlink links link to target. Windows lets only an elevated
// account, or any account in Developer Mode, create a symbolic link; the
// test skips only when Windows refuses this one.
func makeTestSymlink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err != nil && runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) {
		t.Skipf("this Windows account may not create symbolic links: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadBoundedRegularFileRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), 17), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(large, 16); err == nil {
		t.Fatal("oversized managed file was accepted")
	}

	link := filepath.Join(dir, "link")
	makeTestSymlink(t, large, link)
	if _, err := readBoundedRegularFile(link, 64); err == nil {
		t.Fatal("symlinked managed file was accepted")
	}
}

func TestWriteManagedFileAtomicReplacesSymlinkWithoutFollowing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(target, []byte("do-not-change"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeTestSymlink(t, target, path)
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
