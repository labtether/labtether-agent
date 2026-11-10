package system

import "testing"

// Windows sessions had no login time, so the Users page's "since" stayed empty.
func TestWindowsLogonTime(t *testing.T) {
	// 2026-11-10T23:49:26Z as a Windows FILETIME.
	if got := windowsLogonTime(134388281660000000); got != "2026-11-10T23:49:26Z" {
		t.Fatalf("windowsLogonTime = %q", got)
	}
	if got := windowsLogonTime(0); got != "" {
		t.Fatalf("windowsLogonTime(0) = %q, want empty", got)
	}
}
