package agentcore

import (
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	maxSSHHostKeys         = 8
	maxSSHHostKeyFileBytes = 16 * 1024
	sshHostPublicKeyGlob   = "ssh_host_*_key.pub"
)

// readSSHHostKeys returns the SSH server's host public keys from dir, one
// "type base64" line each, for the Hub to pin. Only regular files named
// ssh_host_*_key.pub are read; a symlink is refused, so a private key file is
// never opened. Lines that do not parse as SSH public keys are skipped.
func readSSHHostKeys(dir string) []string {
	paths, err := filepath.Glob(filepath.Join(dir, sshHostPublicKeyGlob))
	if err != nil {
		return nil
	}
	sort.Strings(paths)
	var keys []string
	seen := map[string]bool{}
	for _, path := range paths {
		data, err := readBoundedRegularFile(path, maxSSHHostKeyFileBytes)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			// Re-encode without the comment, which often names the host.
			encoded := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if seen[encoded] {
				continue
			}
			seen[encoded] = true
			keys = append(keys, encoded)
			if len(keys) == maxSSHHostKeys {
				return keys
			}
		}
	}
	return keys
}
