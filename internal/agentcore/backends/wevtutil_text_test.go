package backends

import (
	"context"
	"slices"
	"testing"
	"unicode/utf16"

	"github.com/labtether/protocol"
)

// utf16LE encodes text the way wevtutil /uni:true writes it: a BOM, then UTF-16LE.
func utf16LE(text string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune(text)) {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return out
}

// Event log text outside the console code page used to reach the Hub as "?":
// wevtutil must be asked for UTF-16 and its output decoded.
func TestWindowsLogBackendKeepsNonASCIIEventText(t *testing.T) {
	original := RunWevtutilCommand
	t.Cleanup(func() { RunWevtutilCommand = original })
	var gotArgs [][]string
	RunWevtutilCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotArgs = append(gotArgs, args)
		return utf16LE("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
			"<Provider Name='Microsoft-Windows-RestartManager'/><Level>4</Level>" +
			"<TimeCreated SystemTime='2026-11-10T23:43:34.6615392Z'/></System><RenderingInfo Culture='fr-FR'>" +
			"<Message>Starting session 0 - ‎2026‎-‎11‎-‎10. Tâche planifiée ✓ 日本</Message>" +
			"</RenderingInfo></Event>"), nil
	}

	entries, err := (WindowsLogBackend{Channels: "System"}).QueryEntries(protocol.JournalQueryData{Limit: 5})
	if err != nil {
		t.Fatalf("QueryEntries: %v", err)
	}
	if len(gotArgs) != 1 || !slices.Contains(gotArgs[0], "/uni:true") {
		t.Fatalf("wevtutil args = %v, want /uni:true", gotArgs)
	}
	want := "Starting session 0 - 2026-11-10. Tâche planifiée ✓ 日本"
	if len(entries) != 1 || entries[0].Message != want {
		t.Fatalf("entries = %+v, want one message %q", entries, want)
	}
}

func TestDecodeWevtutilOutputLeavesUTF8Alone(t *testing.T) {
	plain := []byte("<Event><System/></Event>")
	if got := decodeWevtutilOutput(plain); string(got) != string(plain) {
		t.Fatalf("decodeWevtutilOutput(plain) = %q", got)
	}
}
