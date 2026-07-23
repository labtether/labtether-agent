package securityruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	envExecAllowlistMode        = "LABTETHER_EXEC_ALLOWLIST_MODE"
	envExecAllowlistAcceptRisk  = "LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK"
	envExecAllowedBinaries      = "LABTETHER_EXEC_ALLOWED_BINARIES"
	envExecBlockedBinaries      = "LABTETHER_EXEC_BLOCKED_BINARIES"
	envShellAllowlistMode       = "LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE"
	envShellAllowlistAcceptRisk = "LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK"
	envShellAllowlistPrefixes   = "LABTETHER_SHELL_COMMAND_ALLOWLIST_PREFIXES"
	envShellBlockedSubstrings   = "LABTETHER_SHELL_COMMAND_BLOCKED_SUBSTRINGS"
	defaultShellCommandFallback = "command is required"
)

var defaultAllowedExecBinaries = []string{
	"apk",
	"apt",
	"apt-get",
	"ash",
	"bash",
	"brew",
	"cat",
	"choco",
	"cmd",
	"dash",
	"defaults",
	"df",
	"dnf",
	"docker",
	"docker-compose",
	"dpkg-query",
	"dscl",
	"du",
	"ffmpeg",
	"free",
	"grep",
	"gst-inspect-1.0",
	"gst-launch-1.0",
	"head",
	"ifconfig",
	"ip",
	"istats",
	"journalctl",
	"launchctl",
	"loginctl",
	"log",
	"ls",
	"lscpu",
	"netplan",
	"netsh",
	"netstat",
	"networksetup",
	"needs-restarting",
	"nmcli",
	"osascript",
	"osx-cpu-temp",
	"pacman",
	"pbcopy",
	"pbpaste",
	"ping",
	"plutil",
	"powershell",
	"ps",
	"pwsh",
	"route",
	"rpm",
	"sc",
	"sensors",
	"sh",
	"sysctl",
	"system_profiler",
	"systemctl",
	"schtasks",
	"tailscale",
	"tail",
	"tmux",
	"top",
	"uname",
	"uptime",
	"vncserver",
	"tvnserver",
	"wevtutil",
	"winget",
	"winvnc4",
	"who",
	"wl-copy",
	"wl-paste",
	"xvfb",
	"x11vnc",
	"xauth",
	"xsetroot",
	"xterm",
	"yum",
	"xclip",
	"xdotool",
	"ydotool",
	"xrandr",
	"xsel",
	"xset",
	"zsh",
	"zypper",
}

var defaultShellAllowlistPrefixes = []string{
	"cmd /c echo",
	"uptime",
	"uname",
	"df",
	"du",
	"free",
	"ps",
	"top",
	"journalctl",
	"systemctl status",
	"docker ps",
	"docker images",
	"ls",
	"cat",
	"grep",
	"tail",
	"head",
}

// defaultShellBlockedSubstrings lists patterns that are blocked via substring
// matching after lowercasing and whitespace normalization. Use these for
// patterns where substring presence is inherently dangerous regardless of
// surrounding context (e.g. "rm -rf /" can never be benign as a substring).
var defaultShellBlockedSubstrings = []string{
	"rm -rf /",
	":(){ :|:& };:",
	"mkfs",
	// Catch systemctl power-state transitions not covered by token blocking.
	"systemctl poweroff",
	"systemctl reboot",
	"systemctl halt",
}

// defaultShellBlockedTokens lists command words that are blocked only when
// they appear as a standalone word token (not as a substring of another word).
// This prevents false positives: "shutdown" blocks "shutdown now" but not
// "cat shutdown.log". "reboot" blocks "reboot" but not "needs-reboot-check".
var defaultShellBlockedTokens = []string{
	"shutdown",
	"reboot",
	"halt",
	"poweroff",
	"init",
}

var runtimeEnvOverridesState struct {
	sync.RWMutex
	values map[string]string
}

func SetRuntimeEnvOverrides(values map[string]string) {
	cloned := make(map[string]string, len(values))
	for rawKey, rawValue := range values {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			continue
		}
		cloned[key] = strings.TrimSpace(rawValue)
	}

	runtimeEnvOverridesState.Lock()
	defer runtimeEnvOverridesState.Unlock()
	if len(cloned) == 0 {
		runtimeEnvOverridesState.values = nil
		return
	}
	runtimeEnvOverridesState.values = cloned
}

func lookupEnv(key string) (string, bool) {
	runtimeEnvOverridesState.RLock()
	if runtimeEnvOverridesState.values != nil {
		if value, ok := runtimeEnvOverridesState.values[key]; ok {
			runtimeEnvOverridesState.RUnlock()
			return value, true
		}
	}
	runtimeEnvOverridesState.RUnlock()
	return os.LookupEnv(key)
}

func parseBoolEnv(key string, fallback bool) bool {
	raw, _ := lookupEnv(key)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parseBoolEnvWithPresence(key string, fallback bool) (bool, bool) {
	raw, present := lookupEnv(key)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, false
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback, present
	}
	return value, present
}

func parseCSVEnv(key string, fallback []string) []string {
	raw, _ := lookupEnv(key)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return append([]string(nil), fallback...)
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.TrimSpace(part)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return append([]string(nil), fallback...)
	}
	return out
}

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

func toSet(values []string, normalize func(string) string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := normalize(value)
		if key == "" {
			continue
		}
		out[key] = struct{}{}
	}
	return out
}

func ValidateExecBinary(name string) error {
	normalized := normalizeExecutableName(name)
	if normalized == "" {
		return fmt.Errorf("command is required")
	}

	blocked := toSet(parseCSVEnv(envExecBlockedBinaries, nil), normalizeExecutableName)
	if _, found := blocked[normalized]; found {
		return fmt.Errorf("command %q blocked by runtime policy", normalized)
	}

	if !parseBoolEnv(envExecAllowlistMode, true) {
		if !parseBoolEnv(envExecAllowlistAcceptRisk, false) {
			return fmt.Errorf("refusing to run %q: %s=false requires %s=true to acknowledge that disabling the exec allowlist removes a significant security control", normalized, envExecAllowlistMode, envExecAllowlistAcceptRisk)
		}
		return nil
	}

	allowed := toSet(parseCSVEnv(envExecAllowedBinaries, defaultAllowedExecBinaries), normalizeExecutableName)
	if _, found := allowed[normalized]; found {
		return nil
	}

	return fmt.Errorf("command %q is not allowlisted", normalized)
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

func ValidateShellCommand(command string) error {
	args, parseErr := ParseCommandLine(command)
	if parseErr != nil {
		return parseErr
	}
	normalized := normalizeShellCommand(strings.Join(args, " "))

	for _, blocked := range parseCSVEnv(envShellBlockedSubstrings, defaultShellBlockedSubstrings) {
		token := normalizeShellCommand(blocked)
		if token == "" {
			continue
		}
		if strings.Contains(normalized, token) {
			return fmt.Errorf("command blocked by safety policy")
		}
	}

	// Check blocked tokens: matched as whole words to avoid false positives
	// (e.g. "shutdown" blocks "shutdown now" but not "cat shutdown.log").
	for _, tok := range defaultShellBlockedTokens {
		normTok := strings.ToLower(strings.TrimSpace(tok))
		if normTok == "" {
			continue
		}
		if containsCommandToken(normalized, normTok) {
			return fmt.Errorf("command blocked by safety policy")
		}
	}

	if !parseBoolEnv(envShellAllowlistMode, true) {
		if !parseBoolEnv(envShellAllowlistAcceptRisk, false) {
			return fmt.Errorf("refusing shell command: %s=false requires %s=true to acknowledge that disabling the shell allowlist removes a significant security control", envShellAllowlistMode, envShellAllowlistAcceptRisk)
		}
		return nil
	}

	for _, prefix := range parseCSVEnv(envShellAllowlistPrefixes, defaultShellAllowlistPrefixes) {
		prefixArgs, err := ParseCommandLine(prefix)
		if err != nil || len(prefixArgs) == 0 {
			continue
		}
		if commandArgsHavePrefix(args, prefixArgs) {
			if normalizeExecutableName(args[0]) == "cmd" {
				if err := validateWindowsCmdEcho(args); err != nil {
					return err
				}
			}
			return nil
		}
	}

	return fmt.Errorf("command not in allowlist")
}

// NewValidatedShellCommandContext returns a direct executable invocation for
// an allowlisted remote command. Despite the historical name, no shell is
// involved; callers cannot append operators to escape the allowlist.
func NewValidatedShellCommandContext(ctx context.Context, command string) (*exec.Cmd, error) {
	if err := ValidateShellCommand(command); err != nil {
		return nil, err
	}
	args, err := ParseCommandLine(command)
	if err != nil {
		return nil, err
	}
	return NewCommandContext(ctx, args[0], args[1:]...)
}

func NewCommandContext(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if err := ValidateExecBinary(name); err != nil {
		return nil, err
	}
	// #nosec G204 -- command name is validated by ValidateExecBinary allowlist/policy.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = SanitizedChildEnv()
	return cmd, nil
}

func NewCommand(name string, args ...string) (*exec.Cmd, error) {
	if err := ValidateExecBinary(name); err != nil {
		return nil, err
	}
	// #nosec G204 -- command name is validated by ValidateExecBinary allowlist/policy.
	cmd := exec.Command(name, args...)
	cmd.Env = SanitizedChildEnv()
	return cmd, nil
}

func CommandContextCombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd, err := NewCommandContext(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	return CaptureCombinedOutput(cmd, DefaultCommandOutputLimit)
}

func CommandCombinedOutput(name string, args ...string) ([]byte, error) {
	cmd, err := NewCommand(name, args...)
	if err != nil {
		return nil, err
	}
	return CaptureCombinedOutput(cmd, DefaultCommandOutputLimit)
}

func CommandContextOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd, err := NewCommandContext(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	return CaptureOutput(cmd, DefaultCommandOutputLimit)
}

func CommandOutput(name string, args ...string) ([]byte, error) {
	cmd, err := NewCommand(name, args...)
	if err != nil {
		return nil, err
	}
	return CaptureOutput(cmd, DefaultCommandOutputLimit)
}

func CommandRun(name string, args ...string) error {
	cmd, err := NewCommand(name, args...)
	if err != nil {
		return err
	}
	return cmd.Run()
}
