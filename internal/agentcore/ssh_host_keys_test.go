package agentcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Risk: the Hub pins exactly these keys for SSH, so the agent must send only
// real host public keys, never read a private key file, and stay bounded.
func TestReadSSHHostKeys(t *testing.T) {
	dir := t.TempDir()
	host := testSSHPublicKey(t)
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ssh_host_ed25519_key.pub", host+" root@nas01\n")
	write("ssh_host_rsa_key.pub", "not a key\n")
	// A private key file must never be opened, even if its text parses.
	write("ssh_host_ecdsa_key", testSSHPublicKey(t)+"\n")
	if err := os.Symlink(filepath.Join(dir, "ssh_host_ecdsa_key"), filepath.Join(dir, "ssh_host_dsa_key.pub")); err != nil {
		t.Logf("symlink case not checked: %v", err) // Windows without symlink rights
	}

	if got := readSSHHostKeys(dir); len(got) != 1 || got[0] != host {
		t.Fatalf("readSSHHostKeys = %q, want only %q", got, host)
	}
	if got := readSSHHostKeys(filepath.Join(dir, "missing")); len(got) != 0 {
		t.Fatalf("missing dir gave %q, want none", got)
	}

	for i := range maxSSHHostKeys + 2 {
		write(fmt.Sprintf("ssh_host_extra%02d_key.pub", i), testSSHPublicKey(t)+"\n")
	}
	if got := readSSHHostKeys(dir); len(got) != maxSSHHostKeys {
		t.Fatalf("readSSHHostKeys returned %d keys, want the %d bound", len(got), maxSSHHostKeys)
	}
}

func testSSHPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
