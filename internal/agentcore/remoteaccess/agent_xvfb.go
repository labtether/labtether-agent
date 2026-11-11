package remoteaccess

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// ErrSeveralAgentXvfbs refuses the clipboard while the agent runs more than
// one Xvfb: the clipboard request does not say which Remote View session it
// is for, so it could reach another viewer's display.
var ErrSeveralAgentXvfbs = errors.New("Clipboard is off while more than one Remote View session runs on this device.")

// agentXvfbs records the Xvfb displays this agent started, each with its own
// Xauthority file. X clients that serve the Remote View user,
// such as the clipboard, use only these on a device without a desktop
// session. They never scan for a display: another local user can run their
// own X server, and the agent must not send the viewer's clipboard there.
var agentXvfbs struct {
	mu      sync.Mutex
	entries []agentXvfb
}

type agentXvfb struct {
	cmd       *exec.Cmd
	display   string
	xauthPath string
}

// RegisterAgentXvfb records an Xvfb the agent started. xauthPath is the file
// the server was started with, or "none" when it runs without one.
func RegisterAgentXvfb(cmd *exec.Cmd, display, xauthPath string) {
	display = NormalizeX11DisplayIdentifier(display)
	if cmd == nil || display == "" {
		return
	}
	agentXvfbs.mu.Lock()
	defer agentXvfbs.mu.Unlock()
	agentXvfbs.entries = append(agentXvfbs.entries, agentXvfb{cmd: cmd, display: display, xauthPath: strings.TrimSpace(xauthPath)})
}

// ForgetAgentXvfb drops the record of an Xvfb when it is stopped.
func ForgetAgentXvfb(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	agentXvfbs.mu.Lock()
	defer agentXvfbs.mu.Unlock()
	kept := agentXvfbs.entries[:0]
	for _, entry := range agentXvfbs.entries {
		if entry.cmd != cmd {
			kept = append(kept, entry)
		}
	}
	agentXvfbs.entries = kept
}

// AgentXvfbDisplay returns the one Xvfb the agent started and still runs,
// with its Xauthority path ("none" when it has none). It returns an empty
// display when there is none and ErrSeveralAgentXvfbs when there are several.
// An entry counts only while its process has not exited and the display's
// lock file still names that process; anything else is dropped, so a server
// another user starts on the same number after a crash is never used.
func AgentXvfbDisplay() (display, xauthPath string, err error) {
	agentXvfbs.mu.Lock()
	defer agentXvfbs.mu.Unlock()
	live := agentXvfbs.entries[:0]
	for _, entry := range agentXvfbs.entries {
		if agentXvfbAlive(entry) {
			live = append(live, entry)
		}
	}
	agentXvfbs.entries = live
	switch len(live) {
	case 0:
		return "", "", nil
	case 1:
		xauthPath = live[0].xauthPath
		if xauthPath == "" {
			xauthPath = "none"
		}
		return live[0].display, xauthPath, nil
	default:
		return "", "", ErrSeveralAgentXvfbs
	}
}

func agentXvfbAlive(entry agentXvfb) bool {
	if entry.cmd == nil || entry.cmd.Process == nil || entry.cmd.ProcessState != nil {
		return false
	}
	lock := fmt.Sprintf("%s/.X%s-lock", x11LockDir, strings.TrimPrefix(x11ServerIdentity(entry.display), ":"))
	return x11LockOwnedBy(lock, entry.cmd.Process.Pid)
}
