//go:build windows

package agentcore

import (
	"fmt"
	"os"
	"os/user"

	"golang.org/x/sys/windows"
)

func resolveHubSSHKeyTarget() (hubSSHKeyTarget, error) {
	account, err := user.Current()
	if err != nil {
		return hubSSHKeyTarget{}, fmt.Errorf("cannot determine the agent account: %w", err)
	}
	home, _ := os.UserHomeDir()
	return windowsHubSSHKeyTarget(windowsAccount{sid: account.Uid, username: account.Username, home: home}, windowsProgramData())
}

// windowsAdministratorsKeysFile is administrators_authorized_keys under the
// ProgramData folder that sshd itself uses.
func windowsAdministratorsKeysFile() string {
	return windowsAdministratorsKeysPath(windowsProgramData())
}

func windowsProgramData() string {
	if path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && path != "" {
		return path
	}
	if path := os.Getenv("ProgramData"); path != "" {
		return path
	}
	return `C:\ProgramData`
}
