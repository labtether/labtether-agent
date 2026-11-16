//go:build !windows

package agentcore

import (
	"os"
	"testing"
)

// assertPrivateFile fails unless path has mode 0600, so only the agent's own
// account can read it.
func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode=%o, want 600", path, info.Mode().Perm())
	}
}
