package darwin

import "testing"

// Mac devices read "darwin" on their device page; Windows ones read "Microsoft Windows 11 Pro".
func TestApplyMacOSName(t *testing.T) {
	metadata := map[string]string{"os_name": "darwin", "os_version": "27.2", "platform": "darwin"}
	applyMacOSName(metadata)
	if metadata["os_name"] != "macOS" || metadata["os_pretty_name"] != "macOS 27.2" || metadata["platform"] != "darwin" {
		t.Fatalf("metadata = %v", metadata)
	}
}
