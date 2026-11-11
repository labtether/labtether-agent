package system

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// CollectUserSessionsFn is the function used to collect active user sessions.
// It can be overridden in tests.
var CollectUserSessionsFn = CollectUserSessions

// UsersManager handles active user session requests from the hub.
// It carries no persistent state; the struct exists for consistency
// with the other manager types.
type UsersManager struct{}

// NewUsersManager creates a new UsersManager.
func NewUsersManager() *UsersManager { return &UsersManager{} }

// CloseAll is a no-op for UsersManager -- user session requests are stateless
// and require no cleanup.
func (um *UsersManager) CloseAll() {}

// HandleUsersList collects active user sessions and sends them to the hub.
func (um *UsersManager) HandleUsersList(transport MessageSender, msg protocol.Message) {
	var req protocol.UsersListData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("users: invalid users.list request: %v", err)
		return
	}

	sessions, err := CollectUserSessionsFn()

	var errMsg string
	if err != nil {
		errMsg = err.Error()
		log.Printf("users: failed to collect user sessions: %v", err)
	}

	data, marshalErr := json.Marshal(protocol.UsersListedData{
		RequestID: req.RequestID,
		Sessions:  sessions,
		Error:     errMsg,
	})
	if marshalErr != nil {
		log.Printf("users: failed to marshal users.listed response: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgUsersListed,
		ID:   req.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("users: failed to send users.listed for request %s: %v", req.RequestID, sendErr)
	}
}

// CollectUserSessions runs `who` and parses the output to extract active user sessions.
// who output format: username tty    YYYY-MM-DD HH:MM (remote_host)
func CollectUserSessions() ([]protocol.UserSession, error) {
	if runtime.GOOS == "windows" {
		return collectUserSessionsWindows()
	}
	return collectUserSessionsWho()
}

func collectUserSessionsWho() ([]protocol.UserSession, error) {
	whoBin, err := exec.LookPath("who")
	if err != nil {
		return nil, err
	}

	out, err := securityruntime.CommandCombinedOutput(whoBin)
	if err != nil {
		return nil, err
	}

	return ParseUserSessionsOutput(out), nil
}

// whoLocation is the zone `who` prints login times in: the host's own.
var whoLocation = time.Local

// whoNow is the clock that dates a yearless `who` time. Overridable for tests.
var whoNow = time.Now

// parseBSDWhoTime reads macOS `who` login times, which have no year and follow
// the locale: "Oct 30 11:53" or "30 Oct 11:53". A time that would be in the
// future belongs to last year.
func parseBSDWhoTime(fields []string) (time.Time, bool) {
	if len(fields) < 3 {
		return time.Time{}, false
	}
	now := whoNow().In(whoLocation)
	text := strings.Join(fields[:3], " ")
	for _, layout := range []string{"Jan 2 15:04", "2 Jan 15:04"} {
		t, err := time.ParseInLocation(layout, text, whoLocation)
		if err != nil {
			continue
		}
		t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, whoLocation)
		if t.After(now.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, true
	}
	return time.Time{}, false
}

// ParseUserSessionsOutput parses `who` command output into user sessions.
func ParseUserSessionsOutput(out []byte) []protocol.UserSession {
	var sessions []protocol.UserSession
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		session := protocol.UserSession{
			Username: fields[0],
			Terminal: fields[1],
		}

		loginFields := fields[2:]
		if n := len(loginFields); n > 0 {
			last := loginFields[n-1]
			if strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
				loginFields = loginFields[:n-1]
			}
		}

		// Try to parse ISO-style login times first. `who` prints the host's
		// local time; reading it as UTC put logins hours off on any host
		// not set to UTC.
		if len(loginFields) >= 2 {
			dateStr := loginFields[0] + " " + loginFields[1]
			if t, parseErr := time.ParseInLocation("2006-01-02 15:04", dateStr, whoLocation); parseErr == nil {
				session.LoginTime = t.UTC().Format(time.RFC3339)
			} else if t, ok := parseBSDWhoTime(loginFields); ok {
				session.LoginTime = t.UTC().Format(time.RFC3339)
			} else {
				session.LoginTime = strings.Join(loginFields, " ")
			}
		} else if len(loginFields) == 1 {
			session.LoginTime = loginFields[0]
		}

		session.RemoteHost = whoRemoteHost(fields)

		sessions = append(sessions, session)
	}

	return sessions
}

// whoRemoteHost reads the comment `who` prints in parentheses at the end of a
// line: the address a login came from, or ":0" for a local display. A shell
// inside tmux reads "(tmux(4649).%0)": that is a tmux pane on this machine,
// not a remote host, so it gives "". Nested parentheses are kept whole.
func whoRemoteHost(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	last := fields[len(fields)-1]
	if len(last) < 3 || !strings.HasPrefix(last, "(") || !strings.HasSuffix(last, ")") {
		return ""
	}
	comment := last[1 : len(last)-1]
	if strings.HasPrefix(comment, "tmux(") {
		return ""
	}
	return comment
}
