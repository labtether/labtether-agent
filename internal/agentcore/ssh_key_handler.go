package agentcore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/labtether/protocol"
	"golang.org/x/crypto/ssh"
)

// hubSSHKeyMu serializes every read-modify-write of authorized_keys and of the
// key record. Hub messages are handled concurrently, and a key rotation sends
// an install and a remove back to back; without it one rewrite can drop the
// other's change.
var hubSSHKeyMu sync.Mutex

// validateAuthorizedKey asserts that pubKey is a single, valid authorized_keys
// entry with no embedded newlines and no trailing content after the key proper.
// It returns the caller's trimmed original payload unchanged so existing
// installs (matched on byte-equality by MsgSSHKeyRemove) keep working; the
// value is validated but not canonicalized.
func validateAuthorizedKey(pubKey string) (string, error) {
	trimmed := strings.TrimSpace(pubKey)
	if trimmed == "" {
		return "", fmt.Errorf("public key is empty")
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return "", fmt.Errorf("public key must not contain newlines")
	}
	_, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return "", fmt.Errorf("invalid authorized_keys entry: %w", err)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return "", fmt.Errorf("public key payload contains more than one entry")
	}
	return trimmed, nil
}

// handleSSHKeyInstall installs the hub's SSH public key into the current user's
// authorized_keys file, enabling zero-config SSH access from the hub.
func handleSSHKeyInstall(transport agentMessageSender, msg protocol.Message) {
	handleSSHKeyInstallRecorded(transport, msg, "")
}

// handleSSHKeyInstallRecorded installs the Hub key and, when this agent added
// the line, records it at recordPath so uninstall can remove exactly that line.
func handleSSHKeyInstallRecorded(transport agentMessageSender, msg protocol.Message, recordPath string) {
	var req protocol.SSHKeyInstallData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("ssh-key: invalid install request: %v", err)
		return
	}

	pubKey, err := validateAuthorizedKey(req.PublicKey)
	if err != nil {
		log.Printf("ssh-key: rejecting install request: %v", err)
		return
	}

	target, err := resolveHubSSHKeyTarget()
	if err != nil {
		log.Printf("ssh-key: failed to resolve authorized_keys path: %v", err)
		return
	}

	if err := installHubSSHKey(target.path, pubKey, recordPath); err != nil {
		log.Printf("ssh-key: failed to install public key: %v", err)
		return
	}

	// Send confirmation back to hub. An empty username tells the Hub that this
	// account is not an SSH login, so it asks the user for one.
	hostname, _ := os.Hostname()
	homeDir, _ := os.UserHomeDir()
	username := target.sshUser

	resp := protocol.SSHKeyInstalledData{
		Username: username,
		Hostname: hostname,
		HomeDir:  homeDir,
	}
	data, _ := json.Marshal(resp)
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgSSHKeyInstalled,
		Data: data,
	})

	log.Printf("ssh-key: installed hub public key in %s for user %q", target.path, username)
}

// handleSSHKeyRemove removes the hub's SSH public key from the current user's
// authorized_keys file, used during asset decommissioning.
func handleSSHKeyRemove(transport agentMessageSender, msg protocol.Message) {
	handleSSHKeyRemoveRecorded(transport, msg, "")
}

// handleSSHKeyRemoveRecorded removes the Hub key and drops a matching record.
func handleSSHKeyRemoveRecorded(transport agentMessageSender, msg protocol.Message, recordPath string) {
	var req protocol.SSHKeyRemoveData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("ssh-key: invalid remove request: %v", err)
		return
	}

	pubKey, err := validateAuthorizedKey(req.PublicKey)
	if err != nil {
		log.Printf("ssh-key: rejecting remove request: %v", err)
		return
	}

	target, err := resolveHubSSHKeyTarget()
	if err != nil {
		log.Printf("ssh-key: failed to resolve authorized_keys path: %v", err)
		return
	}

	if err := removeHubSSHKey(target.path, pubKey, recordPath); err != nil {
		log.Printf("ssh-key: failed to remove public key: %v", err)
		return
	}

	resp := protocol.SSHKeyInstalledData{Username: target.sshUser} // reuse for confirmation
	hostname, _ := os.Hostname()
	homeDir, _ := os.UserHomeDir()
	resp.Hostname = hostname
	resp.HomeDir = homeDir

	data, _ := json.Marshal(resp)
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgSSHKeyRemoved,
		Data: data,
	})

	log.Printf("ssh-key: removed hub public key")
}

// installHubSSHKey adds the Hub key line and, when this agent added it,
// records the exact line at recordPath so uninstall can remove that line.
func installHubSSHKey(authKeysPath, pubKey, recordPath string) error {
	hubSSHKeyMu.Lock()
	defer hubSSHKeyMu.Unlock()
	added, err := installPublicKey(authKeysPath, pubKey)
	if err != nil {
		return err
	}
	if added && recordPath != "" {
		if err := saveHubSSHKeyRecord(recordPath, hubSSHKeyRecord{AuthorizedKeysPath: authKeysPath, KeyLine: pubKey}); err != nil {
			log.Printf("ssh-key: warning: uninstall will not find the added key line: %v", err)
		}
	}
	return nil
}

// removeHubSSHKey removes the exact Hub key line and drops a matching record.
func removeHubSSHKey(authKeysPath, pubKey, recordPath string) error {
	hubSSHKeyMu.Lock()
	defer hubSSHKeyMu.Unlock()
	if err := removePublicKey(authKeysPath, pubKey); err != nil {
		return err
	}
	if record, ok := loadHubSSHKeyRecord(recordPath); ok && record.KeyLine == pubKey && record.AuthorizedKeysPath == authKeysPath {
		_ = os.Remove(recordPath) // #nosec G703 -- Record path is the fixed file beside the agent token.
	}
	return nil
}

// removePublicKey removes a matching public key line from authorized_keys.
// Callers hold hubSSHKeyMu.
func removePublicKey(authKeysPath, pubKey string) error {
	keyLine := strings.TrimSpace(pubKey)
	_, err := removeAuthorizedKeyLines(authKeysPath, func(line string) bool { return line == keyLine })
	return err
}

// removeAuthorizedKeyLines rewrites authorized_keys without the lines (compared
// trimmed) that match, and reports whether any were removed. Callers hold
// hubSSHKeyMu.
func removeAuthorizedKeyLines(authKeysPath string, match func(line string) bool) (bool, error) {
	existing, err := os.ReadFile(authKeysPath) // #nosec G304 -- authorized_keys path is derived from the managed SSH home directory.
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // nothing to remove
		}
		return false, fmt.Errorf("failed to read authorized_keys: %w", err)
	}

	lines := strings.Split(string(existing), "\n")
	filtered := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" && match(trimmed) {
			removed = true
			continue
		}
		filtered = append(filtered, line)
	}

	if !removed {
		return false, nil // key was not present
	}

	content := strings.Join(filtered, "\n")
	if err := writeAuthorizedKeys(authKeysPath, []byte(content)); err != nil {
		return false, err
	}
	return true, nil
}

// installPublicKey idempotently appends a public key to authorized_keys and
// reports whether it added the line. Callers hold hubSSHKeyMu.
func installPublicKey(authKeysPath, pubKey string) (bool, error) {
	// Ensure .ssh directory exists with correct permissions.
	sshDir := filepath.Dir(authKeysPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return false, fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Read existing authorized_keys.
	existing, err := os.ReadFile(authKeysPath) // #nosec G304 -- authorized_keys path is derived from the managed SSH home directory.
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to read authorized_keys: %w", err)
	}

	// Check if the key is already present.
	keyLine := strings.TrimSpace(pubKey)
	if len(existing) > 0 {
		for _, line := range strings.Split(string(existing), "\n") {
			if strings.TrimSpace(line) == keyLine {
				log.Printf("ssh-key: public key already present")
				return false, nil
			}
		}
	}

	// Append the key.
	content := string(existing)
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += keyLine + "\n"

	if err := writeAuthorizedKeys(authKeysPath, []byte(content)); err != nil {
		return false, err
	}

	return true, nil
}
