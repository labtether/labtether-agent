//go:build windows

package agentcore

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Tokens and device keys live under ProgramData, whose inherited ACL lets
// local Users read files. The staging file must be private before any secret
// byte is written to it.
func TestCreateManagedTempSecretStartsWithPrivateProtectedDACL(t *testing.T) {
	tmp, err := createManagedTemp(t.TempDir(), true)
	if err != nil {
		t.Fatalf("create secret temp: %v", err)
	}
	path := tmp.Name()
	defer os.Remove(path)
	defer tmp.Close()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read DACL: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read security descriptor control: %v", err)
	}
	sddl := sd.String()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("secret temp DACL inherits parent permissions: %s", sddl)
	}
	// BU=Users, WD=Everyone, AU=Authenticated Users, IU=Interactive.
	for _, broad := range []string{";BU)", ";WD)", ";AU)", ";IU)"} {
		if strings.Contains(sddl, broad) {
			t.Fatalf("secret temp DACL grants %s: %s", broad, sddl)
		}
	}
}
