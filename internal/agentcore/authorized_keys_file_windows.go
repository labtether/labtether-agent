//go:build windows

package agentcore

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// keepAuthorizedKeysAccess copies the original file's DACL, including whether
// it is protected from inheritance, onto the temp file before the rename. A
// new file in C:\ProgramData\ssh would otherwise inherit the folder's ACL,
// and OpenSSH ignores an administrators_authorized_keys that grants anyone
// but Administrators and SYSTEM write access.
func keepAuthorizedKeysAccess(_ os.FileInfo, originalPath string, tmp *os.File) error {
	sd, err := windows.GetNamedSecurityInfo(originalPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(tmp.Name(), windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// newAuthorizedKeysAccess gives a new administrators_authorized_keys the ACL
// OpenSSH for Windows requires: full control for SYSTEM and Administrators
// only, not inherited from C:\ProgramData\ssh. A user's own authorized_keys
// keeps the ACL inherited from the profile folder.
func newAuthorizedKeysAccess(target string, tmp *os.File) error {
	if !strings.EqualFold(filepath.Base(target), windowsAdminKeysFileName) {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(tmp.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// syncAuthorizedKeysDir is a no-op on Windows: replaceManagedFile already
// uses MOVEFILE_WRITE_THROUGH.
func syncAuthorizedKeysDir(string) {}
