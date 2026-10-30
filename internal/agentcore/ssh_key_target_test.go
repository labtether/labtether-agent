package agentcore

import "testing"

// Risk: the LocalSystem service saw its name as WORKGROUP\HOST$, missed the
// NT AUTHORITY\SYSTEM name check and wrote the Hub key to the SYSTEM profile,
// which sshd never reads, and reported the machine account as the SSH user.
func TestWindowsHubSSHKeyTarget(t *testing.T) {
	const programData = `C:\ProgramData`
	tests := []struct {
		name    string
		account windowsAccount
		want    hubSSHKeyTarget
	}{
		{"LocalSystem by SID", windowsAccount{sid: "S-1-5-18", username: `WORKGROUP\HOST$`,
			home: `C:\Windows\system32\config\systemprofile`},
			hubSSHKeyTarget{path: `C:\ProgramData\ssh\administrators_authorized_keys`}},
		{"standard user", windowsAccount{sid: "S-1-5-21-1-2-3-1001", username: `HOST\demo`, home: `C:\Users\demo`},
			hubSSHKeyTarget{path: `C:\Users\demo\.ssh\authorized_keys`, sshUser: `HOST\demo`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsHubSSHKeyTarget(tc.account, programData)
			if err != nil || got != tc.want {
				t.Fatalf("windowsHubSSHKeyTarget = (%+v, %v), want %+v", got, err, tc.want)
			}
		})
	}
}
