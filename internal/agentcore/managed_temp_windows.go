//go:build windows

package agentcore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secretFileSecurityDescriptor grants full access only to the agent's process
// identity, LocalSystem and local administrators. "D:P" marks the DACL
// protected, so nothing is inherited from ProgramData, which lets Users read.
func secretFileSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
}

// createManagedTemp creates the staging file for an atomic write. A secret
// file gets its protected DACL in the CreateFile call itself, so there is no
// moment between creation and hardenSecretFile in which another local account
// could open it and keep a handle to the token or device key.
func createManagedTemp(dir string, secret bool) (*os.File, error) {
	if !secret {
		return os.CreateTemp(dir, managedTempPattern)
	}
	sd, err := secretFileSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	prefix := strings.TrimSuffix(managedTempPattern, "*")
	for range 16 {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		path := filepath.Join(dir, prefix+hex.EncodeToString(suffix[:]))
		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			sa,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(handle), path), nil
	}
	return nil, errors.New("could not create a unique managed temporary file")
}
