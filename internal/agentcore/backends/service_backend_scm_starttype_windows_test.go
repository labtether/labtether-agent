//go:build windows

package backends

import "testing"

// The Event Log service starts with Windows on every supported version.
func TestWindowsServiceStartTypesReadsTheServiceManager(t *testing.T) {
	words := windowsServiceStartTypes([]string{"EventLog", "ltqa-no-such-service"})
	if words["eventlog"] != "enabled" {
		t.Fatalf("EventLog start type = %q, want enabled (all: %v)", words["eventlog"], words)
	}
	if _, ok := words["ltqa-no-such-service"]; ok {
		t.Fatalf("a missing service got a start type: %v", words)
	}
}
