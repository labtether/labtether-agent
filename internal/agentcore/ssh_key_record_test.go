package agentcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// Uninstall and purge must remove the Hub key line this agent added, so the
// Hub's key does not keep login access after the agent is gone. A line that
// was already there stays.
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
	existing := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExistingUserKeyForTestsOnly user@example.com\n"
	if err := os.MkdirAll(filepath.Dir(authorizedKeysPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorizedKeysPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	hubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDXvBALRC6pB8/bY8wpyWU5AYk+3NDJxLtJqstVU3OI6 labtether-hub"
	raw, err := json.Marshal(protocol.SSHKeyInstallData{PublicKey: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	handleSSHKeyInstallRecorded(transport, protocol.Message{Type: protocol.MsgSSHKeyInstall, Data: raw}, hubSSHKeyRecordPath(tokenFile))
	_ = waitForCapturedAgentMessage(t, messages, protocol.MsgSSHKeyInstalled, 2*time.Second)

	changed, err := RemoveRecordedHubSSHKey(tokenFile)
	if err != nil || changed != authorizedKeysPath {
		t.Fatalf("remove recorded key = %q, %v", changed, err)
	}
	content, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), hubKey) || !strings.Contains(string(content), strings.TrimSpace(existing)) {
		t.Fatalf("authorized_keys after uninstall = %q", content)
	}
	if _, err := os.Stat(hubSSHKeyRecordPath(tokenFile)); !os.IsNotExist(err) {
		t.Fatalf("record left behind: %v", err)
	}
}
