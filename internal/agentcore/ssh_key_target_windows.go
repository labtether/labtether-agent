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
	member, rights := administratorsMembership()
	return windowsHubSSHKeyTarget(windowsAccount{
		sid: account.Uid, username: account.Username, home: home,
		adminMember: member, adminRights: rights,
	}, windowsProgramData())
}

// administratorsMembership reports whether the agent's account is in
// Administrators (the group is in its token, possibly deny-only under UAC)
// and whether the group is enabled, which is what writing
// administrators_authorized_keys needs.
func administratorsMembership() (member, rights bool) {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, false
	}
	rights, _ = windows.Token(0).IsMember(adminSID)
	if groups, err := windows.GetCurrentProcessToken().GetTokenGroups(); err == nil {
		for _, group := range groups.AllGroups() {
			if group.Sid.Equals(adminSID) {
				member = true
				break
			}
		}
	}
	return member || rights, rights
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
