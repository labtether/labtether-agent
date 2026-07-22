//go:build !windows

package agentcore

import "os"

func hardenSecretFile(path string) error {
	return os.Chmod(path, 0o600)
}
