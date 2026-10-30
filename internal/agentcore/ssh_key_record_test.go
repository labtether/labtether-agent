package agentcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
	"golang.org/x/crypto/ssh"
)

// newTestAuthorizedKey returns a fresh "ssh-ed25519 <key>" line without a comment.
func newTestAuthorizedKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
}

// Uninstall and purge must remove the Hub key lines, including a key the Hub
// has since rotated, so the Hub's key does not keep login access after the
// agent is gone. User keys, uncommented lines and lines with options stay.
func TestRecordedHubSSHKeyIsRemovedOnUninstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses HOME for the authorized_keys location")
	}
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	authorizedKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	rotated := newTestAuthorizedKey(t)
	kept := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExistingUserKeyForTestsOnly user@example.com",
		rotated,
		`from="192.0.2.10" ` + rotated + " labtether-hub",
	}
	existing := strings.Join(append([]string{kept[0], rotated + " labtether-hub"}, kept[1:]...), "\n") + "\n"
	if err := os.MkdirAll(filepath.Dir(authorizedKeysPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorizedKeysPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	hubKey := newTestAuthorizedKey(t) + " labtether-hub"
	raw, err := json.Marshal(protocol.SSHKeyInstallData{PublicKey: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	handleSSHKeyInstallRecorded(transport, protocol.Message{Type: protocol.MsgSSHKeyInstall, Data: raw}, hubSSHKeyRecordPath(tokenFile))
	_ = waitForCapturedAgentMessage(t, messages, protocol.MsgSSHKeyInstalled, 2*time.Second)

	changed, err := RemoveRecordedHubSSHKey(tokenFile)
	if err != nil || len(changed) != 1 || changed[0] != authorizedKeysPath {
		t.Fatalf("remove Hub key = %v, %v", changed, err)
	}
	content, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(content)), strings.Join(kept, "\n"); got != want {
		t.Fatalf("authorized_keys after uninstall:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Stat(hubSSHKeyRecordPath(tokenFile)); !os.IsNotExist(err) {
		t.Fatalf("record left behind: %v", err)
	}
}

// Hub key messages are handled concurrently; every rewrite of
// authorized_keys must keep the others' changes.
func TestConcurrentHubSSHKeyInstallsKeepEveryLine(t *testing.T) {
	authorizedKeysPath := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	keys := make([]string, 16)
	for index := range keys {
		keys[index] = newTestAuthorizedKey(t) + " labtether-hub"
	}
	var wg sync.WaitGroup
	for _, key := range keys {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			if err := installHubSSHKey(authorizedKeysPath, key, ""); err != nil {
				t.Errorf("install: %v", err)
			}
		}(key)
	}
	wg.Wait()
	content, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if !strings.Contains(string(content), key) {
			t.Fatalf("a concurrent install lost key %q", key)
		}
	}
}
