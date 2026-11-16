package backends

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const (
	journalQueryCommandTimeout = 20 * time.Second
	// journalStreamMaxLine is the longest journal line the live stream
	// reads; a longer one is skipped.
	journalStreamMaxLine = 256 * 1024
)

// LinuxLogBackend implements LogBackend using journalctl.
type LinuxLogBackend struct{}

var (
	// JournalLookPath is the function used to find journalctl. Overridable for tests.
	JournalLookPath = exec.LookPath
	// NewJournalCommandContext is the function used to build journal commands. Overridable for tests.
	NewJournalCommandContext = securityruntime.NewCommandContext
	// JournalQueryTimeout is the timeout for journal queries. Overridable for tests.
	JournalQueryTimeout = journalQueryCommandTimeout
)

// QueryEntries runs a historical journal query and returns entries.
func (LinuxLogBackend) QueryEntries(req protocol.JournalQueryData) ([]protocol.LogStreamData, error) {
	if _, err := JournalLookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("journalctl is not available on this host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), JournalQueryTimeout)
	defer cancel()

	args := BuildJournalQueryArgs(req)
	cmd, err := NewJournalCommandContext(ctx, "journalctl", args...)
	if err != nil {
		return nil, fmt.Errorf("journalctl command blocked by runtime policy: %w", err)
	}
	out, err := securityruntime.CaptureCombinedOutput(cmd, securityruntime.DefaultCommandOutputLimit)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("journalctl query timed out")
		}
		stderr := strings.TrimSpace(string(out))
		if stderr != "" {
			return nil, fmt.Errorf("journalctl query failed: %s", stderr)
		}
		return nil, fmt.Errorf("journalctl query failed: %w", err)
	}

	entries := make([]protocol.LogStreamData, 0, NormalizedJournalLimit(req.Limit))
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(nil, 256*1024) // Grow for long lines; keep idle streams small.
	for scanner.Scan() {
		entry, ok := ParseJournalLine(scanner.Bytes())
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse journal output: %w", err)
	}

	return entries, nil
}

// StreamEntries streams journal entries via `journalctl -f`.
func (LinuxLogBackend) StreamEntries(ctx context.Context, emit func(protocol.LogStreamData)) error {
	if _, err := JournalLookPath("journalctl"); err != nil {
		return ErrLogStreamingUnsupported
	}

	cmd, err := NewJournalCommandContext(ctx, "journalctl", "-f", "--output=json", "-n", "0")
	if err != nil {
		return fmt.Errorf("failed to build journalctl stream command: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to open journalctl stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start journalctl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(nil, journalStreamMaxLine) // Grow for long lines; keep idle streams small.
	scanner.Split(skipLongLines(journalStreamMaxLine, func() {
		log.Printf("logmgr: skipped a journal entry of %d bytes or more", journalStreamMaxLine)
	}))
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return nil
		default:
		}

		entry, ok := ParseJournalLine(scanner.Bytes())
		if !ok {
			continue
		}
		emit(entry)
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil && ctx.Err() == nil {
		return fmt.Errorf("journalctl scanner error: %w", scanErr)
	}
	if waitErr != nil && ctx.Err() == nil {
		return fmt.Errorf("journalctl stream failed: %w", waitErr)
	}

	return nil
}

// skipLongLines splits as bufio.ScanLines does, but drops a line of max bytes
// or more (max being the scanner's buffer limit) and goes on with the next
// one. With plain ScanLines such a line stops the scanner with
// bufio.ErrTooLong; nothing reads journalctl's output any more, so it blocks
// on a full pipe, cmd.Wait never returns, and the live stream stays silent
// until the agent restarts. Skipping loses only that entry; restarting
// journalctl would also lose what it had already written after it and
// everything logged during the restart wait. onSkip runs once per line.
func skipLongLines(max int, onSkip func()) bufio.SplitFunc {
	skipping := false
	var split bufio.SplitFunc
	split = func(data []byte, atEOF bool) (int, []byte, error) {
		if skipping {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				return len(data), nil, nil
			}
			skipping = false
			// The Scanner reads more before it splits again after an advance
			// without a token, so the next line must be returned now, or it
			// would wait for the entry after it.
			advance, token, err := split(data[i+1:], atEOF)
			return i + 1 + advance, token, err
		}
		advance, token, err := bufio.ScanLines(data, atEOF)
		if advance == 0 && token == nil && err == nil && len(data) >= max {
			skipping = true
			onSkip()
			return len(data), nil, nil
		}
		return advance, token, err
	}
	return split
}

// BuildJournalQueryArgs builds the arguments for a journalctl query.
func BuildJournalQueryArgs(req protocol.JournalQueryData) []string {
	limit := NormalizedJournalLimit(req.Limit)
	args := []string{
		"--no-pager",
		"--output=json",
		"-n", strconv.Itoa(limit),
		"-r",
	}
	if since := strings.TrimSpace(req.Since); since != "" {
		args = append(args, "--since", since)
	}
	if until := strings.TrimSpace(req.Until); until != "" {
		args = append(args, "--until", until)
	}
	if unit := strings.TrimSpace(req.Unit); unit != "" {
		args = append(args, "-u", unit)
	}
	if priority := strings.TrimSpace(req.Priority); priority != "" {
		args = append(args, "-p", priority)
	}
	if search := strings.TrimSpace(req.Search); search != "" {
		args = append(args, "--grep", search)
	}
	return args
}

// NormalizedJournalLimit clamps the journal query limit to a sane range.
func NormalizedJournalLimit(raw int) int {
	if raw <= 0 {
		return 200
	}
	if raw > 1000 {
		return 1000
	}
	return raw
}
