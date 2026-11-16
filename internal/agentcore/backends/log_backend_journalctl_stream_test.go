package backends

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// journalLine is a journalctl JSON line of exactly n bytes before its newline.
func journalLine(n int) string {
	const head, tail = `{"MESSAGE":"`, `"}`
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail + "\n"
}

// A journal line of 256 KiB or more stopped the scanner with
// bufio.ErrTooLong. Nothing read journalctl's output after that, cmd.Wait
// never returned, and the live log stream stayed silent until the agent
// restarted. The stream must skip such a line (one at the limit and one
// three times over it) and go on at once with the next, keep a line one byte
// under the limit, and still end when its context is cancelled.
func TestJournalStreamSkipsALineTooLongAndGoesOn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "journal.jsonl")
	lines := `{"MESSAGE":"before"}` + "\n" +
		journalLine(journalStreamMaxLine-1) +
		journalLine(journalStreamMaxLine) +
		journalLine(3*journalStreamMaxLine) +
		`{"MESSAGE":"after"}` + "\n"
	if err := os.WriteFile(output, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	originalLook, originalCommand := JournalLookPath, NewJournalCommandContext
	t.Cleanup(func() { JournalLookPath, NewJournalCommandContext = originalLook, originalCommand })
	JournalLookPath = func(string) (string, error) { return "/bin/sh", nil }
	NewJournalCommandContext = func(ctx context.Context, _ string, _ ...string) (*exec.Cmd, error) {
		// journalctl --follow writes what it has, then keeps running.
		return exec.CommandContext(ctx, "/bin/sh", "-c", `/bin/cat "$1"; exec /bin/sleep 30`, "sh", output), nil
	}

	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (LinuxLogBackend{}).StreamEntries(ctx, func(entry protocol.LogStreamData) {
			mu.Lock()
			got = append(got, entry.Message)
			mu.Unlock()
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		count := len(got)
		mu.Unlock()
		if count >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	summary := make([]string, len(got))
	for i, message := range got {
		summary[i] = message
		if len(message) > 16 {
			summary[i] = "long"
		}
	}
	mu.Unlock()
	if strings.Join(summary, ",") != "before,long,after" {
		t.Fatalf("entries = %v, want before, the line one byte under the limit, after", summary)
	}
	if len(got[1]) != journalStreamMaxLine-1-len(`{"MESSAGE":""}`) {
		t.Fatalf("kept long message has %d bytes", len(got[1]))
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end after its context was cancelled")
	}
}
