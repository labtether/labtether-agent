package sysconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCopyDirPreservesNetplanFilesAndSymlinks(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dst := filepath.Join(t.TempDir(), "dst")
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(src, "50-test.yaml")
	if err := os.WriteFile(file, []byte("network: {version: 2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	modified := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(file, modified, modified); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("50-test.yaml", filepath.Join(src, "linked.yaml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("nested", filepath.Join(src, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"linked.yaml": "50-test.yaml", "linked-dir": "nested"} {
		got, err := os.Readlink(filepath.Join(dst, name))
		if err != nil || got != want {
			t.Fatalf("symlink %s: target=%q error=%v, want %q", name, got, err, want)
		}
	}
	got, err := os.ReadFile(filepath.Join(dst, "50-test.yaml"))
	if err != nil || string(got) != "network: {version: 2}\n" {
		t.Fatalf("copied file=%q error=%v", got, err)
	}
	info, err := os.Stat(filepath.Join(dst, "50-test.yaml"))
	if err != nil || info.Mode().Perm() != 0o600 || !info.ModTime().Equal(modified) {
		t.Fatalf("copied file metadata=%v error=%v", info, err)
	}
}
