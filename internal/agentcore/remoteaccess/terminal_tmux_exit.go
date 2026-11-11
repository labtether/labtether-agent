package remoteaccess

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const (
	// terminalShellExitedReason tells the Hub the shell ended by itself. For a
	// tmux terminal it also says the tmux session is gone.
	terminalShellExitedReason = "shell exited"
	// terminalTmuxDetachedReason tells the Hub the tmux client ended while its
	// session is still running, so the saved session can be attached again.
	terminalTmuxDetachedReason = "tmux client detached"
	// TerminalReportsTmuxDetachMeta is the heartbeat key that tells the Hub
	// this agent sends terminalTmuxDetachedReason.
	TerminalReportsTmuxDetachMeta = "terminal_reports_tmux_detach"

	tmuxSessionCheckTimeout = 3 * time.Second
)

// tmuxClientCloseReason says why a tmux terminal ended by itself. Only a
// plain "no such session" answer from tmux counts as an exit: if tmux cannot
// be asked, the session is reported as still there, so the Hub keeps it.
func (tm *TerminalManager) tmuxClientCloseReason(tmuxPath, session string) string {
	ctx, cancel := context.WithTimeout(context.Background(), tmuxSessionCheckTimeout)
	defer cancel()
	cmd, err := securityruntime.NewCommandContext(ctx, tmuxPath, "has-session", "-t", "="+session)
	if err != nil {
		return terminalTmuxDetachedReason
	}
	cmd.Env = append(securityruntime.SanitizedChildEnv(), tm.tmuxEnv...)
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil && exitErr.ExitCode() == 1 {
		return terminalShellExitedReason
	}
	return terminalTmuxDetachedReason
}
