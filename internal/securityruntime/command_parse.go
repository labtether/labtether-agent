package securityruntime

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func normalizeExecutableName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.ReplaceAll(trimmed, "\\", "/")
	trimmed = filepath.Base(trimmed)
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return ""
	}
	normalized := strings.ToLower(trimmed)
	// Windows resolves executable names with PATHEXT and returns the concrete
	// `.exe` path. The policy is intentionally defined in extensionless binary
	// names so the same allowlist works across supported operating systems.
	if strings.HasSuffix(normalized, ".exe") {
		normalized = strings.TrimSuffix(normalized, ".exe")
	}
	return normalized
}

func normalizeShellCommand(raw string) string {
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(raw)))
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// ParseCommandLine parses the operator-supplied command into an executable and
// argument vector without invoking a shell. Shell control operators are
// rejected instead of being interpreted. This intentionally supports only the
// quoting needed to pass literal arguments; expansion, redirection, pipelines,
// command substitution, and compound commands are not part of the remote
// command protocol.
func ParseCommandLine(raw string) ([]string, error) {
	const maxCommandBytes = 64 * 1024
	if len(raw) > maxCommandBytes {
		return nil, fmt.Errorf("command exceeds %d byte limit", maxCommandBytes)
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return nil, errors.New("command contains a NUL byte")
	}

	var (
		args      []string
		current   strings.Builder
		quote     rune
		escaped   bool
		haveToken bool
	)
	flush := func() {
		if haveToken {
			args = append(args, current.String())
			current.Reset()
			haveToken = false
		}
	}

	for _, r := range raw {
		if escaped {
			if r == '\n' || r == '\r' {
				return nil, errors.New("multiline commands are not supported")
			}
			current.WriteRune(r)
			haveToken = true
			escaped = false
			continue
		}

		if quote != 0 {
			switch {
			case r == quote:
				quote = 0
				haveToken = true
			case r == '\\' && quote == '"':
				escaped = true
			case r == '\n' || r == '\r':
				return nil, errors.New("multiline commands are not supported")
			default:
				current.WriteRune(r)
				haveToken = true
			}
			continue
		}

		switch r {
		case '\'', '"':
			quote = r
			haveToken = true
		case '\\':
			escaped = true
			haveToken = true
		case ' ', '\t':
			flush()
		case '\n', '\r':
			return nil, errors.New("multiline commands are not supported")
		case ';', '|', '&', '<', '>', '`':
			return nil, fmt.Errorf("shell control operator %q is not supported", r)
		default:
			current.WriteRune(r)
			haveToken = true
		}
	}
	if escaped {
		return nil, errors.New("command ends with an incomplete escape")
	}
	if quote != 0 {
		return nil, errors.New("command contains an unterminated quote")
	}
	flush()
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, errors.New(defaultShellCommandFallback)
	}
	return args, nil
}

func commandArgsHavePrefix(args, prefix []string) bool {
	if len(prefix) == 0 || len(args) < len(prefix) {
		return false
	}
	for i := range prefix {
		if !strings.EqualFold(args[i], prefix[i]) {
			return false
		}
	}
	return true
}

func validateWindowsCmdEcho(args []string) error {
	if len(args) < 4 || normalizeExecutableName(args[0]) != "cmd" ||
		!strings.EqualFold(args[1], "/c") || !strings.EqualFold(args[2], "echo") {
		return fmt.Errorf("cmd /c is limited to an echo probe with a non-empty ASCII value")
	}
	for _, arg := range args[3:] {
		if arg == "" {
			return fmt.Errorf("cmd /c echo probe values must not be empty")
		}
		for _, char := range arg {
			switch {
			case char >= 'a' && char <= 'z':
			case char >= 'A' && char <= 'Z':
			case char >= '0' && char <= '9':
			case char == '.', char == '_', char == '-', char == ':':
			default:
				return fmt.Errorf("cmd /c echo probe values may contain only ASCII letters, digits, dot, underscore, dash, or colon")
			}
		}
	}
	return nil
}

// containsCommandToken returns true if any word in the normalized command
// exactly matches the given token. This prevents "shutdown" from matching
// "cat shutdown.log" while still catching "sudo shutdown -h now".
func containsCommandToken(normalizedCmd, token string) bool {
	for _, word := range strings.Fields(normalizedCmd) {
		if word == token {
			return true
		}
	}
	return false
}
