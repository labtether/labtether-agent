package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
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

// hubSSHKeyComment is the comment the Hub puts on its key line.
const hubSSHKeyComment = "labtether-hub"

// isHubSSHKeyLine matches a Hub key line by its comment: one valid key, no
// options in front, comment exactly labtether-hub. User keys, uncommented
// lines and lines with options never match.
func isHubSSHKeyLine(line string) bool {
	if !strings.HasSuffix(line, " "+hubSSHKeyComment) {
		return false
	}
	_, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	return err == nil && len(options) == 0 && comment == hubSSHKeyComment && strings.TrimSpace(string(rest)) == ""
}

// RemoveRecordedHubSSHKey removes the Hub key lines from authorized_keys: the
// exact line this agent recorded adding, and any line commented
// labtether-hub (for example a key the Hub has since rotated). It searches
// the recorded file, or the agent account's own file(s) when there is no
// record, deletes the record, and returns the files it changed.
func RemoveRecordedHubSSHKey(tokenFilePath string) ([]string, error) {
	hubSSHKeyMu.Lock()
	defer hubSSHKeyMu.Unlock()

	recordPath := hubSSHKeyRecordPath(tokenFilePath)
	recordedLine := ""
	var paths []string
	if recordPath != "" {
		if _, err := os.Lstat(recordPath); err == nil {
			record, ok := loadHubSSHKeyRecord(recordPath)
			if !ok {
				return nil, fmt.Errorf("the Hub SSH key record at %s is not valid; check the authorized_keys files by hand", recordPath)
			}
			recordedLine, paths = record.KeyLine, []string{record.AuthorizedKeysPath}
		}
	}
	if len(paths) == 0 {
		paths = defaultHubSSHKeyPaths()
	}

	var changed []string
	for _, path := range paths {
		removed, err := removeAuthorizedKeyLines(path, func(line string) bool {
			return (recordedLine != "" && line == recordedLine) || isHubSSHKeyLine(line)
		})
		if err != nil {
			return changed, err
		}
		if removed {
			changed = append(changed, path)
		}
	}
	if recordPath != "" {
		if err := os.Remove(recordPath); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 -- Record path is the fixed file beside the agent token.
			return changed, err
		}
	}
	return changed, nil
}

// defaultHubSSHKeyPaths lists where this account's agent installs the Hub key,
// plus the Administrators file on Windows, where the SYSTEM service installs.
func defaultHubSSHKeyPaths() []string {
	var paths []string
	if target, err := resolveHubSSHKeyTarget(); err == nil {
		paths = append(paths, target.path)
	}
	if admin := windowsAdministratorsKeysFile(); admin != "" && (len(paths) == 0 || !strings.EqualFold(paths[0], admin)) {
		paths = append(paths, admin)
	}
	return paths
}

// runSSHKeyCommand handles "labtether-agent ssh-key remove", which uninstall
// and purge run before deleting the agent.
func runSSHKeyCommand(cfg RuntimeConfig, args []string) int {
	if len(args) != 1 || strings.TrimSpace(strings.ToLower(args[0])) != "remove" {
		fmt.Println("usage: labtether-agent ssh-key remove")
		fmt.Println("Removes the Hub SSH key lines (the one this agent added and any commented labtether-hub) from authorized_keys.")
		return 1
	}
	changed, err := RemoveRecordedHubSSHKey(cfg.TokenFilePath)
	for _, path := range changed {
		fmt.Printf("removed the Hub SSH key from %s\n", path)
	}
	if err != nil {
		fmt.Printf("could not remove the Hub SSH key: %v\n", err)
		return 1
	}
	if len(changed) == 0 {
		fmt.Println("no Hub SSH key found")
	}
	return 0
}
