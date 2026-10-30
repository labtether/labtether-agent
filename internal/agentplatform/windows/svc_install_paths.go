//go:build windows

package windows

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	winsys "golang.org/x/sys/windows"
)

// stateDirSecurityDescriptor makes BUILTIN\Administrators the owner and gives
// full control only to LocalSystem and Administrators, inherited by new files
// and folders. Standard users can neither read nor create files there.
const stateDirSecurityDescriptor = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// secureStateDirectory creates or locks the agent's state folder before the
// SYSTEM service uses it. A folder a standard user created earlier could hold
// planted files (agent-config.json.tmp, ca.crt) that the service would trust,
// so files owned by any other account stop the install.
func secureStateDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a plain folder", dir)
	}
	sd, err := winsys.SecurityDescriptorFromString(stateDirSecurityDescriptor)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := winsys.SetNamedSecurityInfo(dir, winsys.SE_FILE_OBJECT,
		winsys.OWNER_SECURITY_INFORMATION|winsys.DACL_SECURITY_INFORMATION|winsys.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("lock %s: %w", dir, err)
	}

	// Checked after locking, so nothing new can appear in between.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var foreign []string
	for _, entry := range entries {
		trusted, err := ownedByAdministrators(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if !trusted {
			foreign = append(foreign, entry.Name())
		}
	}
	if len(foreign) > 0 {
		return fmt.Errorf("%s contains files owned by another account (%s); remove them and run install again", dir, strings.Join(foreign, ", "))
	}
	return nil
}

// ownedByAdministrators reports whether path is owned by LocalSystem, the
// Administrators group or the current elevated account.
func ownedByAdministrators(path string) (bool, error) {
	sd, err := winsys.GetNamedSecurityInfo(path, winsys.SE_FILE_OBJECT, winsys.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner.IsWellKnown(winsys.WinLocalSystemSid) || owner.IsWellKnown(winsys.WinBuiltinAdministratorsSid) {
		return true, nil
	}
	user, err := winsys.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	return owner.Equals(user.User.Sid), nil
}

// installServiceBinary copies the running executable to
// %ProgramFiles%\LabTether\labtether-agent.exe, where only administrators can
// write, and returns that path. A SYSTEM service registered at a
// user-writable path (such as Downloads) lets that user replace the binary.
func installServiceBinary(source string) (string, error) {
	programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	dir := filepath.Join(programFiles, "LabTether")
	dest := filepath.Join(dir, "labtether-agent.exe")
	if sourceInfo, err := os.Stat(source); err == nil {
		if destInfo, err := os.Stat(dest); err == nil && os.SameFile(sourceInfo, destInfo) {
			return dest, nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	data, err := os.ReadFile(source) // #nosec G304 -- Source is this program's own executable.
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil { // #nosec G306 -- A service binary must be executable; the folder inherits the Program Files ACL.
		return "", err
	}
	return dest, nil
}
