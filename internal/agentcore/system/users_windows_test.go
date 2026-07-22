//go:build windows

package system

import "testing"

func TestCollectUserSessionsWindows(t *testing.T) {
	sessions, err := collectUserSessionsWindows()
	if err != nil {
		t.Fatalf("collectUserSessionsWindows: %v", err)
	}
	for _, session := range sessions {
		if session.Username == "" || session.Terminal == "" || session.SessionType == "" {
			t.Fatalf("incomplete Windows session: %+v", session)
		}
	}
}

func TestWindowsSessionType(t *testing.T) {
	for input, want := range map[string]string{
		"Console":   "console",
		"RDP-Tcp#3": "rdp",
		"Services":  "windows",
	} {
		if got := windowsSessionType(input); got != want {
			t.Fatalf("windowsSessionType(%q) = %q, want %q", input, got, want)
		}
	}
}
