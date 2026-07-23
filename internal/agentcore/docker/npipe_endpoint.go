package docker

import (
	"fmt"
	"strings"
)

const (
	dockerNpipePrefix       = "npipe:////./pipe/"
	dockerNpipeNameMaxBytes = 128
)

// NormalizeDockerNpipeEndpoint recognizes and validates the one named-pipe
// form LabTether permits on the wire. matched is true for any npipe scheme,
// including malformed input, so callers never fall through to Unix dialing.
func NormalizeDockerNpipeEndpoint(raw string) (normalized string, matched bool, err error) {
	value := strings.TrimSpace(raw)
	if len(value) < len("npipe:") || !strings.EqualFold(value[:len("npipe:")], "npipe:") {
		return "", false, nil
	}
	if !strings.HasPrefix(value, dockerNpipePrefix) {
		return "", true, fmt.Errorf("npipe path must use canonical %s<name> form", dockerNpipePrefix)
	}

	name := strings.TrimPrefix(value, dockerNpipePrefix)
	if name == "" {
		return "", true, fmt.Errorf("npipe name cannot be empty")
	}
	if len(name) > dockerNpipeNameMaxBytes {
		return "", true, fmt.Errorf("npipe name exceeds %d bytes", dockerNpipeNameMaxBytes)
	}
	if !isDockerNpipeNameStart(name[0]) {
		return "", true, fmt.Errorf("npipe name must begin with an ASCII letter or digit")
	}
	if strings.Contains(name, "..") {
		return "", true, fmt.Errorf("npipe name cannot contain traversal segments")
	}
	if name[len(name)-1] == '.' {
		return "", true, fmt.Errorf("npipe name cannot end with punctuation")
	}
	for i := 1; i < len(name); i++ {
		if !isDockerNpipeNameChar(name[i]) {
			return "", true, fmt.Errorf("npipe name contains unsupported characters")
		}
	}
	return dockerNpipePrefix + name, true, nil
}

func dockerNpipeNativePath(canonical string) string {
	return `\\.\pipe\` + strings.TrimPrefix(canonical, dockerNpipePrefix)
}

func isDockerNpipeNameStart(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func isDockerNpipeNameChar(ch byte) bool {
	return isDockerNpipeNameStart(ch) || ch == '_' || ch == '-' || ch == '.'
}
