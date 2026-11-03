package system

import (
	"testing"
	"time"
)

// `who` prints local time. The agent labelled it UTC, so on a host at UTC+11
// a 21:15 login showed as 21:15Z, which every client showed as 08:15 the
// next day.
func TestWhoLoginTimesAreTheHostsLocalTime(t *testing.T) {
	saved := whoLocation
	t.Cleanup(func() { whoLocation = saved })
	whoLocation = time.FixedZone("UTC+11", 11*60*60)

	sessions := ParseUserSessionsOutput([]byte("root     pts/0        2026-11-03 21:15 (192.0.2.10)\n"))
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions", len(sessions))
	}
	if got := sessions[0].LoginTime; got != "2026-11-03T10:15:00Z" {
		t.Fatalf("login time %s, want 2026-11-03T10:15:00Z", got)
	}
}
