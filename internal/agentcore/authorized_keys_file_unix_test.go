//go:build !windows

package agentcore

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testUserKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com"
	testHubKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb6rWb0RxS8DcxMv0hp5MDaVo3LLxyF7ZqJ1qEsS0B2 labtether-hub"
)

// Risk: authorized_keys was truncated and rewritten in place, so a crash could
// leave it empty and lock the user out of SSH. The replacement must keep the
// other keys and the file mode, and leave no temp file in ~/.ssh.
func TestAuthorizedKeysRewriteKeepsContentModeAndNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(testUserKey+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}

	if added, err := installPublicKey(path, testHubKey); err != nil || !added {
		t.Fatalf("installPublicKey = (%v, %v), want (true, nil)", added, err)
	}
	assertAuthorizedKeys(t, path, testUserKey+"\n"+testHubKey+"\n", 0o640)

	if err := removePublicKey(path, testHubKey); err != nil {
		t.Fatalf("removePublicKey: %v", err)
	}
	assertAuthorizedKeys(t, path, testUserKey+"\n", 0o640)
}

// Risk: renaming over a symlinked authorized_keys would replace the link
// with a plain file and stop updating the file it pointed to.
func TestAuthorizedKeysRewriteKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keys-real")
	if err := os.WriteFile(target, []byte(testUserKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "authorized_keys")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := installPublicKey(link, testHubKey); err != nil {
		t.Fatalf("installPublicKey: %v", err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("authorized_keys is no longer a symlink: %v", err)
	}
	assertAuthorizedKeys(t, target, testUserKey+"\n"+testHubKey+"\n", 0o600)
}

func assertAuthorizedKeys(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("authorized_keys = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("authorized_keys mode = %o, want %o", info.Mode().Perm(), mode)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".authorized_keys.labtether-tmp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temp files left behind: %v (%v)", matches, err)
	}
}
