package agentcore

import (
	"errors"
	"fmt"
	"strings"
)

// hubSSHKeyTarget is where the Hub key goes for the account the agent runs as.
type hubSSHKeyTarget struct {
	path    string
	sshUser string // "" for an account that cannot log in over SSH
}

// windowsAccount describes the Windows account the agent runs as.
type windowsAccount struct {
	sid      string
	username string
	home     string
	// adminMember: the account is in Administrators, even if UAC filtered
	// that group out of the agent's token. adminRights: the group is enabled,
	// so the agent can write files only Administrators may change.
	adminMember bool
	adminRights bool
}

const (
	localSystemSID              = "S-1-5-18"
	windowsAdminKeysFileName    = "administrators_authorized_keys"
	windowsUserKeysRelativePath = `\.ssh\authorized_keys`
)

// windowsHubSSHKeyTarget picks the file Windows OpenSSH reads for the agent's
// account. LocalSystem is matched by SID: the agent sees its name as the
// machine account (for example WORKGROUP\HOST$), not NT AUTHORITY\SYSTEM.
func windowsHubSSHKeyTarget(account windowsAccount, programData string) (hubSSHKeyTarget, error) {
	if strings.EqualFold(account.sid, localSystemSID) {
		// LocalSystem is not an SSH login; the Hub asks the user for one.
		return hubSSHKeyTarget{path: windowsAdministratorsKeysPath(programData)}, nil
	}
	if account.adminMember {
		// sshd reads keys for Administrators members from the shared file
		// only (Match Group administrators), never from the user's profile.
		path := windowsAdministratorsKeysPath(programData)
		if !account.adminRights {
			return hubSSHKeyTarget{}, fmt.Errorf(
				"needs administrator rights: %s is in Administrators, so OpenSSH reads its keys from %s",
				account.username, path)
		}
		return hubSSHKeyTarget{path: path, sshUser: account.username}, nil
	}
	if strings.TrimSpace(account.home) == "" {
		return hubSSHKeyTarget{}, errors.New("cannot determine home directory")
	}
	return hubSSHKeyTarget{
		path:    strings.TrimRight(account.home, `\/`) + windowsUserKeysRelativePath,
		sshUser: account.username,
	}, nil
}

// windowsAdministratorsKeysPath is the file OpenSSH for Windows reads for every
// member of Administrators (sshd_config: Match Group administrators).
func windowsAdministratorsKeysPath(programData string) string {
	return strings.TrimRight(programData, `\/`) + `\ssh\` + windowsAdminKeysFileName
}
