package x11input

import (
	"strings"
	"testing"
)

// Risk: the re-started helper inherits the agent's API token when a caller
// does not set its environment.
func TestNewCommandStartsWithTheSanitizedEnvironment(t *testing.T) {
	t.Setenv("LABTETHER_API_TOKEN", "ltqa-api-token")
	cmd, err := NewCommand("down", "38")
	if err != nil {
		t.Fatalf("NewCommand: %v", err)
	}
	for _, entry := range cmd.Environ() {
		if strings.Contains(entry, "ltqa-api-token") {
			t.Fatalf("the helper would inherit %q", entry)
		}
	}
}
