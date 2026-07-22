package sysconfig

import (
	"strings"
	"testing"
)

func TestUnsupportedPlatformDisplaysReturnsHonestUnavailableState(t *testing.T) {
	displays, err := unsupportedPlatformDisplays("freebsd")
	if err == nil {
		t.Fatal("expected unsupported display enumeration to return an error")
	}
	if !strings.Contains(err.Error(), "freebsd") {
		t.Fatalf("error %q does not name the unsupported platform", err)
	}
	if len(displays) != 0 {
		t.Fatalf("unsupported platform returned fabricated displays: %+v", displays)
	}
}
