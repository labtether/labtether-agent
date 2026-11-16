//go:build windows

package agentcore

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// assertPrivateFile fails unless only the agent's account, LocalSystem and
// Administrators can open path. Windows reports every writable file as mode
// 0666, so the access list is what keeps the agent token from other local
// accounts. These are the rules the Windows app applies before it trusts the
// token file the agent saved (SecureFile.IsPrivateRegularFile): no inherited
// entries, an allowed owner, and allow entries for allowed accounts only.
func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read access list of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read security descriptor control of %s: %v", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s inherits its folder's access list: %s", path, sd)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read current account: %v", err)
	}
	allowed := []*windows.SID{user.User.Sid}
	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(known)
		if err != nil {
			t.Fatalf("build well-known SID: %v", err)
		}
		allowed = append(allowed, sid)
	}
	isAllowed := func(sid *windows.SID) bool {
		for _, candidate := range allowed {
			if sid.Equals(candidate) {
				return true
			}
		}
		return false
	}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !isAllowed(owner) {
		t.Fatalf("%s owner is not the agent's account, SYSTEM or Administrators: %s (err=%v)", path, sd, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no access list, so everyone can open it: %s (err=%v)", path, sd, err)
	}
	userCanOpen := false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("read entry %d of %s: %v", i, path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("%s has an entry that is not a plain allow entry: %s", path, sd)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !isAllowed(sid) {
			t.Fatalf("%s lets %s open it: %s", path, sid, sd)
		}
		if sid.Equals(user.User.Sid) {
			userCanOpen = true
		}
	}
	if !userCanOpen {
		t.Fatalf("%s does not let the agent's own account open it: %s", path, sd)
	}
}
