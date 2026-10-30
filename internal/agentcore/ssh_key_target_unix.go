//go:build !windows

package agentcore

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

func resolveHubSSHKeyTarget() (hubSSHKeyTarget, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return hubSSHKeyTarget{}, fmt.Errorf("cannot determine home directory: %w", err)
	}
	username := ""
	if account, err := user.Current(); err == nil {
		username = account.Username
	}
	return hubSSHKeyTarget{path: filepath.Join(home, ".ssh", "authorized_keys"), sshUser: username}, nil
}

// windowsAdministratorsKeysFile is empty outside Windows.
func windowsAdministratorsKeysFile() string { return "" }
