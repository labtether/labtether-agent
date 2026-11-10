package remoteaccess

import "os"

// tmuxStartArgs creates the named session or attaches to it, starts a new
// session's shell in dir, and hides tmux's status line for that session only.
// The session is how a terminal survives a dropped connection; the person
// asked for a shell, not for tmux, so its bar stays out of the way. Their own
// tmux sessions keep their settings.
func tmuxStartArgs(session, dir string) []string {
	args := []string{"new-session", "-A", "-s", session}
	if dir != "" {
		args = append(args, "-c", dir)
	}
	return append(args, ";", "set-option", "status", "off")
}

// terminalStartDir is the folder a new shell opens in: the home folder of the
// account the agent runs as. Empty means "leave it to the agent's own folder".
func terminalStartDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	if info, statErr := os.Stat(home); statErr != nil || !info.IsDir() {
		return ""
	}
	return home
}
