package securityruntime

import (
	"os"
	"strings"
)

// allowedChildEnv contains only ambient process state that child programs need
// to locate executables, temporary directories, user profiles, and desktop
// sessions. Credential-bearing variables are deliberately not inferred by
// name: new or uncommon variables fail closed instead of leaking into a remote
// shell or helper process.
var allowedChildEnv = map[string]struct{}{
	"ALLUSERSPROFILE":           {},
	"APPDATA":                   {},
	"COLORTERM":                 {},
	"COMMONPROGRAMFILES":        {},
	"COMMONPROGRAMFILES(X86)":   {},
	"COMMONPROGRAMW6432":        {},
	"COMPUTERNAME":              {},
	"COMSPEC":                   {},
	"DBUS_SESSION_BUS_ADDRESS":  {},
	"DESKTOP_SESSION":           {},
	"DISPLAY":                   {},
	"HOME":                      {},
	"HOMEDRIVE":                 {},
	"HOMEPATH":                  {},
	"LANG":                      {},
	"LANGUAGE":                  {},
	"LOCALAPPDATA":              {},
	"LOGNAME":                   {},
	"NO_COLOR":                  {},
	"NUMBER_OF_PROCESSORS":      {},
	"OS":                        {},
	"PATH":                      {},
	"PATHEXT":                   {},
	"PROCESSOR_ARCHITECTURE":    {},
	"PROCESSOR_IDENTIFIER":      {},
	"PROCESSOR_LEVEL":           {},
	"PROCESSOR_REVISION":        {},
	"PROGRAMDATA":               {},
	"PROGRAMFILES":              {},
	"PROGRAMFILES(X86)":         {},
	"PROGRAMW6432":              {},
	"PUBLIC":                    {},
	"PWD":                       {},
	"SHELL":                     {},
	"SYSTEMDRIVE":               {},
	"SYSTEMROOT":                {},
	"TEMP":                      {},
	"TERM":                      {},
	"TMP":                       {},
	"TMPDIR":                    {},
	"TZ":                        {},
	"USER":                      {},
	"USERDOMAIN":                {},
	"USERDOMAIN_ROAMINGPROFILE": {},
	"USERNAME":                  {},
	"USERPROFILE":               {},
	"WAYLAND_DISPLAY":           {},
	"WINDIR":                    {},
	"XAUTHORITY":                {},
	"XDG_CURRENT_DESKTOP":       {},
	"XDG_RUNTIME_DIR":           {},
	"XDG_SESSION_TYPE":          {},
}

// SanitizedChildEnv returns a minimal allowlisted process environment for
// remotely started shells, PTYs, and helper programs.
func SanitizedChildEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || !isAllowedChildEnvKey(key) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func isAllowedChildEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if _, ok := allowedChildEnv[upper]; ok {
		return true
	}
	return strings.HasPrefix(upper, "LC_")
}
