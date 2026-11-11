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

// macOS who prints "Oct 30 11:53" (or "30 Oct 11:53" in day-first locales),
// which reached the Hub as raw text with no year.
func TestWhoLoginTimesInMacOSFormats(t *testing.T) {
	savedLocation, savedNow := whoLocation, whoNow
	t.Cleanup(func() { whoLocation, whoNow = savedLocation, savedNow })
	whoLocation = time.FixedZone("UTC+11", 11*60*60)
	whoNow = func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, whoLocation) }

	for _, line := range []string{"demo     console  Oct 30 11:53", "demo     console  30 Oct 11:53"} {
		sessions := ParseUserSessionsOutput([]byte(line + "\n"))
		if len(sessions) != 1 || sessions[0].LoginTime != "2026-10-30T00:53:00Z" {
			t.Fatalf("%q: sessions = %+v", line, sessions)
		}
	}
	// A December login seen in November is last year's.
	sessions := ParseUserSessionsOutput([]byte("demo ttys001 Dec 24 09:00\n"))
	if len(sessions) != 1 || sessions[0].LoginTime != "2025-12-23T22:00:00Z" {
		t.Fatalf("December session = %+v", sessions)
	}
}

// A shell in LabTether's own terminal runs inside tmux, so `who` prints
// "(tmux(4649).%0)". The Users page showed "4649).%0" as where it came from.
func TestWhoRemoteHostOfTmuxPanesAndAddresses(t *testing.T) {
	out := "root     pts/1        2026-11-11 03:19 (tmux(4649).%0)\n" +
		"demo     pts/3        2026-11-11 03:36 (192.0.2.10)\n" +
		"demo     tty7         2026-11-11 03:00 (:0)\n" +
		"demo     tty1         2026-11-11 02:00\n"
	sessions := ParseUserSessionsOutput([]byte(out))
	want := []string{"", "192.0.2.10", ":0", ""}
	if len(sessions) != len(want) {
		t.Fatalf("got %d sessions, want %d: %#v", len(sessions), len(want), sessions)
	}
	for i, w := range want {
		if sessions[i].RemoteHost != w {
			t.Fatalf("session %d remote host = %q, want %q", i, sessions[i].RemoteHost, w)
		}
	}
}
