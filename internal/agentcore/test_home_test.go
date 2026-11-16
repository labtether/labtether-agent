package agentcore

import (
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
)

// useTestHome makes dir the home folder for one test. Windows takes the home
// folder from USERPROFILE, not HOME; with HOME alone the tests on the Windows
// lab VM wrote applied-config.json into the real profile of the account
// running them.
func useTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// useTestHubSSHKeyFile makes the Hub key handlers use home's
// .ssh/authorized_keys and returns that path. Elsewhere the real lookup
// already reads the home folder. On Windows an elevated account's key goes
// to the machine's administrators_authorized_keys, which a test must not
// change: on the Windows lab VM the old test left its key in that file.
func useTestHubSSHKeyFile(t *testing.T, home string) string {
	t.Helper()
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if runtime.GOOS != "windows" {
		return path
	}
	account, err := user.Current()
	if err != nil {
		t.Fatalf("read current account: %v", err)
	}
	previous := hubSSHKeyTargetFor
	hubSSHKeyTargetFor = func() (hubSSHKeyTarget, error) {
		return hubSSHKeyTarget{path: path, sshUser: account.Username}, nil
	}
	t.Cleanup(func() { hubSSHKeyTargetFor = previous })
	return path
}
