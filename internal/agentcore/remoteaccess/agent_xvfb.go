package remoteaccess

import (
	"os/exec"
	"strings"
	"sync"
)

// agentXvfbs records the Xvfb displays this agent started, each with its own
// Xauthority file, newest last. X clients that serve the Remote View user,
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

// AgentXvfbDisplay returns the newest Xvfb the agent started and still runs,
// with its Xauthority path ("none" when it has none).
func AgentXvfbDisplay() (display, xauthPath string, ok bool) {
	agentXvfbs.mu.Lock()
	defer agentXvfbs.mu.Unlock()
	if len(agentXvfbs.entries) == 0 {
		return "", "", false
	}
	newest := agentXvfbs.entries[len(agentXvfbs.entries)-1]
	xauthPath = newest.xauthPath
	if xauthPath == "" {
		xauthPath = "none"
	}
	return newest.display, xauthPath, true
}
