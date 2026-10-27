package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hubSSHKeyRecordName is the file beside the agent token that records the
// exact authorized_keys line this agent added for the Hub, so uninstall and
// purge can remove that line and nothing else.
const (
	hubSSHKeyRecordName     = "hub-ssh-key.json"
	maxHubSSHKeyRecordBytes = 16 * 1024
)

type hubSSHKeyRecord struct {
	AuthorizedKeysPath string `json:"authorized_keys_path"`
	KeyLine            string `json:"key_line"`
}

func hubSSHKeyRecordPath(tokenFilePath string) string {
	if strings.TrimSpace(tokenFilePath) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(tokenFilePath), hubSSHKeyRecordName)
}

func saveHubSSHKeyRecord(path string, record hubSSHKeyRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeManagedFileAtomic(path, raw, 0o600, true)
}

// loadHubSSHKeyRecord reads a record and accepts it only when it names one
// valid key line in a file called authorized_keys or
// administrators_authorized_keys, so a planted record cannot be used to
// delete lines from any other file.
func loadHubSSHKeyRecord(path string) (hubSSHKeyRecord, bool) {
	var record hubSSHKeyRecord
	if path == "" {
		return record, false
	}
	raw, err := readBoundedRegularFile(path, maxHubSSHKeyRecordBytes)
	if err != nil || json.Unmarshal(raw, &record) != nil {
		return hubSSHKeyRecord{}, false
	}
	keyLine, err := validateAuthorizedKey(record.KeyLine)
	if err != nil || keyLine != record.KeyLine {
		return hubSSHKeyRecord{}, false
	}
	base := strings.ToLower(filepath.Base(record.AuthorizedKeysPath))
	if !filepath.IsAbs(record.AuthorizedKeysPath) || (base != "authorized_keys" && base != "administrators_authorized_keys") {
		return hubSSHKeyRecord{}, false
	}
	return record, true
}

// TokenFilePath returns the configured agent token path
// (LABTETHER_TOKEN_FILE or the platform default).
func TokenFilePath() string {
	return strings.TrimSpace(envOrDefault("LABTETHER_TOKEN_FILE", defaultTokenFile))
}

// StateDirectory returns the directory that holds the agent token and its
// other state files.
func StateDirectory() string {
	return filepath.Dir(TokenFilePath())
}

// RemoveRecordedHubSSHKey removes the authorized_keys line this agent added
// for the Hub and deletes the record. It returns the file it changed, or ""
// when no line was recorded.
func RemoveRecordedHubSSHKey(tokenFilePath string) (string, error) {
	recordPath := hubSSHKeyRecordPath(tokenFilePath)
	if recordPath == "" {
		return "", nil
	}
	if _, err := os.Lstat(recordPath); errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	record, ok := loadHubSSHKeyRecord(recordPath)
	if !ok {
		return "", fmt.Errorf("the Hub SSH key record at %s is not valid; check the authorized_keys files by hand", recordPath)
	}
	if err := removePublicKey(record.AuthorizedKeysPath, record.KeyLine); err != nil {
		return "", err
	}
	if err := os.Remove(recordPath); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 -- Record path is the fixed file beside the agent token.
		return record.AuthorizedKeysPath, err
	}
	return record.AuthorizedKeysPath, nil
}

// runSSHKeyCommand handles "labtether-agent ssh-key remove", which uninstall
// and purge run before deleting the agent.
func runSSHKeyCommand(cfg RuntimeConfig, args []string) int {
	if len(args) != 1 || strings.TrimSpace(strings.ToLower(args[0])) != "remove" {
		fmt.Println("usage: labtether-agent ssh-key remove")
		fmt.Println("Removes the Hub SSH key line this agent added to authorized_keys.")
		return 1
	}
	changed, err := RemoveRecordedHubSSHKey(cfg.TokenFilePath)
	if err != nil {
		fmt.Printf("could not remove the Hub SSH key: %v\n", err)
		return 1
	}
	if changed == "" {
		fmt.Println("no Hub SSH key was added by this agent")
		return 0
	}
	fmt.Printf("removed the Hub SSH key from %s\n", changed)
	return 0
}
