package backends

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// RunDarwinLogShow runs `log show` with args. Overridable for tests.
var RunDarwinLogShow = func(ctx context.Context, args ...string) ([]byte, error) {
	return securityruntime.CommandContextCombinedOutput(ctx, "log", args...)
}

// darwinRecentWindows are the look-back windows a relative query tries, newest
// first. `log show` prints oldest first and a Mac writes tens of MB a minute at
// the default level, so one run over the last hour filled the output cap with
// the hour's first seconds: the System Log view showed lines an hour old.
var darwinRecentWindows = []time.Duration{15 * time.Second, 2 * time.Minute, 15 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

// queryDarwinLog returns the newest entries that match req. A relative or
// missing "since" is read in growing windows that end now, stopping once the
// limit is met, the requested span is covered, or a window's output no longer
// fits; a fixed range is read once.
func queryDarwinLog(ctx context.Context, req protocol.JournalQueryData) ([]protocol.LogStreamData, error) {
	start, end, last := ResolveDarwinLogRange(req.Since, req.Until)
	if last == "" {
		args := append(darwinLogShowBaseArgs(req), "--start", start)
		if end != "" {
			args = append(args, "--end", end)
		}
		entries, _, err := runDarwinLogShow(ctx, args, req)
		return entries, err
	}
	span, err := time.ParseDuration(darwinDurationText(last))
	if err != nil || span <= 0 {
		span = time.Hour
	}
	limit := NormalizedJournalLimit(req.Limit)
	var best []protocol.LogStreamData
	for _, window := range darwinRecentWindows {
		if window > span {
			window = span
		}
		entries, truncated, runErr := runDarwinLogShow(ctx, append(darwinLogShowBaseArgs(req), "--last", darwinLastText(window)), req)
		if runErr != nil {
			if best != nil {
				return best, nil
			}
			return nil, runErr
		}
		if truncated && best != nil {
			return best, nil // the wider window's capture is its oldest part
		}
		best = entries
		if truncated || len(entries) >= limit || window >= span {
			return best, nil
		}
	}
	return best, nil
}

func runDarwinLogShow(ctx context.Context, args []string, req protocol.JournalQueryData) ([]protocol.LogStreamData, bool, error) {
	out, err := RunDarwinLogShow(ctx, args...)
	if err == nil {
		entries, parseErr := parseDarwinLogOutput(out, req)
		return entries, false, parseErr
	}
	if ctx.Err() == context.DeadlineExceeded {
		return nil, false, fmt.Errorf("system log query timed out")
	}
	if errors.Is(err, securityruntime.ErrCommandOutputLimit) {
		entries, parseErr := parseDarwinLogOutput(out, req)
		return entries, true, parseErr
	}
	if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
		return nil, false, fmt.Errorf("system log query failed: %s", TruncateCommandOutput([]byte(trimmed), MaxCommandOutputBytes))
	}
	return nil, false, fmt.Errorf("system log query failed: %w", err)
}

func darwinLogShowBaseArgs(req protocol.JournalQueryData) []string {
	args := []string{"show", "--style", "ndjson", "--color", "none"}
	switch strings.ToLower(strings.TrimSpace(req.Priority)) {
	case "debug":
		args = append(args, "--debug")
	case "info":
		args = append(args, "--info")
	}
	return append(args, "--predicate", DarwinLogPredicate(req))
}

// DarwinLogPredicate filters in `log show` itself, so a filtered search reads
// matching lines only instead of the newest few MB of everything. Error and
// warning priorities keep error and fault messages (macOS has no warning
// level); a unit matches the subsystem or process; text searches the message.
// The unit and text filters on parsed entries still apply afterwards.
func DarwinLogPredicate(req protocol.JournalQueryData) string {
	parts := []string{"eventType == logEvent"}
	if maxRank, ok := priorityMaxRank(strings.ToLower(strings.TrimSpace(req.Priority))); ok && maxRank <= 4 {
		parts = append(parts, "(messageType == error OR messageType == fault)")
	}
	if unit := normalizeUnitFilter(req.Unit); unit != "" {
		quoted := darwinPredicateString(unit)
		parts = append(parts, "(subsystem CONTAINS[c] "+quoted+" OR process CONTAINS[c] "+quoted+")")
	}
	if search := strings.TrimSpace(req.Search); search != "" {
		parts = append(parts, "eventMessage CONTAINS[c] "+darwinPredicateString(search))
	}
	return strings.Join(parts, " AND ")
}

// darwinPredicateString quotes text as an NSPredicate string literal.
func darwinPredicateString(text string) string {
	text = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, text)
	text = strings.ReplaceAll(text, `\`, `\\`)
	return `"` + strings.ReplaceAll(text, `"`, `\"`) + `"`
}

// darwinDurationText turns log's "30m", "2d" or "1w" into a Go duration.
func darwinDurationText(last string) string {
	if n := len(last); n > 1 {
		switch last[n-1] {
		case 'd':
			return fmt.Sprintf("%sh", multiplyDigits(last[:n-1], 24))
		case 'w':
			return fmt.Sprintf("%sh", multiplyDigits(last[:n-1], 24*7))
		}
	}
	return last
}

func multiplyDigits(digits string, by int) string {
	value := 0
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "0"
		}
		value = value*10 + int(r-'0')
	}
	return fmt.Sprintf("%d", value*by)
}

// darwinLastText formats a window for `log show --last` (seconds, minutes or hours).
func darwinLastText(window time.Duration) string {
	switch {
	case window%time.Hour == 0:
		return fmt.Sprintf("%dh", int(window/time.Hour))
	case window%time.Minute == 0:
		return fmt.Sprintf("%dm", int(window/time.Minute))
	default:
		return fmt.Sprintf("%ds", int(window/time.Second))
	}
}
