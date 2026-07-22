//go:build windows

package sysconfig

import (
	"strings"
	"testing"
)

func TestWindowsClipboardFailsClosedInServiceSessionZero(t *testing.T) {
	original := windowsClipboardCurrentSessionID
	windowsClipboardCurrentSessionID = func() (uint32, error) { return 0, nil }
	t.Cleanup(func() { windowsClipboardCurrentSessionID = original })

	_, _, readErr := PlatformClipboardRead("text")
	if readErr == nil || !strings.Contains(readErr.Error(), "service session 0") {
		t.Fatalf("expected service-session read rejection, got %v", readErr)
	}
	if writeErr := PlatformClipboardWriteText("qa-marker"); writeErr == nil || !strings.Contains(writeErr.Error(), "service session 0") {
		t.Fatalf("expected service-session write rejection, got %v", writeErr)
	}
	if imageErr := PlatformClipboardWriteImage("unused"); imageErr == nil || !strings.Contains(imageErr.Error(), "service session 0") {
		t.Fatalf("expected service-session image rejection, got %v", imageErr)
	}
}
