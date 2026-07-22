package backends

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectCrontabsFromPathsWithFSFailsWhenNoSourceReadable(t *testing.T) {
	readDir := func(string) ([]os.DirEntry, error) {
		return nil, fs.ErrPermission
	}
	readFile := func(string) ([]byte, error) {
		return nil, fs.ErrPermission
	}

	entries, err := collectCrontabsFromPathsWithFS(
		[]string{"/spool/users"},
		"/etc/cron.d",
		"/etc/crontab",
		readDir,
		readFile,
	)
	if err == nil {
		t.Fatal("expected terminal error when no configured source is readable")
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected entries from unreadable sources: %+v", entries)
	}
	for _, want := range []string{"no configured crontab source is readable", "/spool/users", "/etc/cron.d", "/etc/crontab"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestCollectCrontabsFromPathsWithFSPreservesPartialEntriesAndError(t *testing.T) {
	userDir := t.TempDir()
	goodPath := filepath.Join(userDir, "alice")
	blockedPath := filepath.Join(userDir, "bob")
	if err := os.WriteFile(goodPath, []byte("*/5 * * * * /usr/local/bin/backup\n"), 0o600); err != nil {
		t.Fatalf("write readable crontab: %v", err)
	}
	if err := os.WriteFile(blockedPath, []byte("0 * * * * /usr/local/bin/blocked\n"), 0o600); err != nil {
		t.Fatalf("write blocked crontab fixture: %v", err)
	}

	readFile := func(path string) ([]byte, error) {
		if path == blockedPath {
			return nil, fs.ErrPermission
		}
		return os.ReadFile(path)
	}
	entries, err := collectCrontabsFromPathsWithFS(
		[]string{userDir},
		"",
		"",
		os.ReadDir,
		readFile,
	)
	if err == nil {
		t.Fatal("expected partial collection error")
	}
	if !strings.Contains(err.Error(), blockedPath) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("partial error %q does not identify the unreadable source", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%+v, want the one readable crontab", entries)
	}
	if entries[0].User != "alice" || entries[0].Command != "/usr/local/bin/backup" {
		t.Fatalf("unexpected preserved entry: %+v", entries[0])
	}
}

func TestCollectCrontabsFromPathsWithFSIgnoresMissingAlternateWhenAnotherSourceIsReadable(t *testing.T) {
	readDir := func(path string) ([]os.DirEntry, error) {
		if path == "/available" {
			return []os.DirEntry{}, nil
		}
		return nil, fs.ErrNotExist
	}
	readFile := func(string) ([]byte, error) {
		return nil, fs.ErrNotExist
	}

	entries, err := collectCrontabsFromPathsWithFS(
		[]string{"/missing", "/available"},
		"/also-missing",
		"/missing-crontab",
		readDir,
		readFile,
	)
	if err != nil {
		t.Fatalf("missing optional alternatives should not poison a readable empty source: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}
