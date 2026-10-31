package remoteaccess

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

// maxProbedX11Display is the highest display number the scan checks (:0-:99).
const maxProbedX11Display = 99

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

	lockFile := fmt.Sprintf("/tmp/.X%s-lock", strings.TrimPrefix(server, ":"))
	if _, err := os.Stat(lockFile); err == nil {
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
