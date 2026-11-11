package remoteaccess

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

// maxProbedX11Display is the highest display number the scan checks (:0-:99).
const maxProbedX11Display = 99

// x11LockDir holds the X servers' /tmp/.X<n>-lock files (a variable for tests).
var x11LockDir = "/tmp"

// x11LockHeld reports whether an X server's lock file belongs to a running
// process. The agent stops its Xvfb with SIGKILL, which leaves the lock (and
// socket) behind; a stale lock made the next Remote View session treat the
// dead display as live and fail with "VNC server not ready" instead of
// starting a new Xvfb. A lock whose content is not a PID still counts.
func x11LockHeld(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return true
	}
	return processAlive(pid)
}

// displayProbe answers "is this X11 display running?" for many displays. It
// reads the desktop session (loginctl) and login list (who) at most once,
// however many displays it checks. Under the systemd unit's PrivateTmp the
// /tmp/.X*-lock files are hidden, so every display falls through to these
// lookups; running them once per display made a 100-display scan take
// longer than the Hub waits for a desktop diagnose reply.
type displayProbe struct {
	session      DesktopSessionInfo
	sessionKnown bool
	users        []protocol.UserSession
	usersErr     error
	usersKnown   bool
}

// IsDisplayAvailable checks whether an X11 display appears to be running
// by looking for its lock file or an active graphical login using that display.
func IsDisplayAvailable(display string) bool {
	return (&displayProbe{}).available(display)
}

// AppendDetectedActiveDisplays adds every running X11 display to dst.
func AppendDetectedActiveDisplays(dst []string) []string {
	return (&displayProbe{}).appendActive(dst)
}

func (p *displayProbe) available(display string) bool {
	display = NormalizeX11DisplayIdentifier(display)
	if display == "" {
		return false
	}
	server := x11ServerIdentity(display)

	if x11LockHeld(fmt.Sprintf("%s/.X%s-lock", x11LockDir, strings.TrimPrefix(server, ":"))) {
		return true
	}

	if !p.sessionKnown {
		p.session = DetectDesktopSessionFn()
		p.sessionKnown = true
	}
	if p.session.Type == DesktopSessionTypeX11 && x11ServerIdentity(p.session.Display) == server {
		return true
	}

	if !p.usersKnown {
		p.users, p.usersErr = system.CollectUserSessionsFn()
		p.usersKnown = true
	}
	if p.usersErr != nil {
		return false
	}
	for _, session := range p.users {
		if x11ServerIdentity(session.RemoteHost) == server {
			return true
		}
		if server == ":0" && strings.EqualFold(strings.TrimSpace(session.Terminal), "seat0") {
			return true
		}
	}
	return false
}

func (p *displayProbe) appendActive(dst []string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, display := range dst {
		normalized := NormalizeX11DisplayIdentifier(display)
		if normalized == "" {
			continue
		}
		seen[normalized] = struct{}{}
	}

	for i := 0; i <= maxProbedX11Display; i++ {
		display := fmt.Sprintf(":%d", i)
		if _, ok := seen[display]; ok {
			continue
		}
		if !p.available(display) {
			continue
		}
		seen[display] = struct{}{}
		dst = append(dst, display)
	}
	sort.Strings(dst)
	return dst
}
