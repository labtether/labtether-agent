package backends

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

func osLogLine(clock, message string) string {
	return fmt.Sprintf(`{"timestamp":"2026-11-11 12:%s.000000+1100","eventMessage":%q,"messageType":"Default","subsystem":"com.example","eventType":"logEvent"}`+"\n", clock, message)
}

func lastArg(args []string) string {
	for i := range args {
		if args[i] == "--last" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// One `log show --last 1h` filled the output cap with the hour's first
// seconds, so the System Log view showed lines an hour old. The query must
// read the newest window first.
func TestDarwinLogQueryReadsTheNewestWindowFirst(t *testing.T) {
	original := RunDarwinLogShow
	t.Cleanup(func() { RunDarwinLogShow = original })
	var windows []string
	RunDarwinLogShow = func(_ context.Context, args ...string) ([]byte, error) {
		windows = append(windows, lastArg(args))
		if strings.Contains(strings.Join(args, " "), "--debug") {
			t.Fatalf("debug messages asked for without a debug priority: %v", args)
		}
		return []byte(osLogLine("17:58", "older") + osLogLine("17:59", "newer") + osLogLine("18:00", "newest")), nil
	}
	entries, err := queryDarwinLog(context.Background(), protocol.JournalQueryData{Since: "1h ago", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(windows, ",") != "15s" || len(entries) != 2 || entries[0].Message != "newest" || entries[1].Message != "newer" {
		t.Fatalf("windows=%v entries=%+v, want the 15s window's two newest", windows, entries)
	}
}

func TestDarwinLogQueryWidensUntilTheSpanAndKeepsCompleteResults(t *testing.T) {
	original := RunDarwinLogShow
	t.Cleanup(func() { RunDarwinLogShow = original })
	var windows []string
	RunDarwinLogShow = func(_ context.Context, args ...string) ([]byte, error) {
		windows = append(windows, lastArg(args))
		return []byte(osLogLine("18:00", "only one")), nil
	}
	if _, err := queryDarwinLog(context.Background(), protocol.JournalQueryData{Since: "30m ago", Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(windows, ",") != "15s,2m,15m,30m" {
		t.Fatalf("windows = %v, want 15s,2m,15m,30m", windows)
	}

	// A wider window whose output no longer fits holds only its oldest part:
	// keep the narrower, complete result.
	windows = nil
	RunDarwinLogShow = func(_ context.Context, args ...string) ([]byte, error) {
		windows = append(windows, lastArg(args))
		if lastArg(args) == "15s" {
			return []byte(osLogLine("18:00", "recent")), nil
		}
		return []byte(osLogLine("02:00", "an hour old")), securityruntime.ErrCommandOutputLimit
	}
	entries, err := queryDarwinLog(context.Background(), protocol.JournalQueryData{Limit: 5})
	if err != nil || len(entries) != 1 || entries[0].Message != "recent" {
		t.Fatalf("entries=%+v err=%v, want the recent line only", entries, err)
	}
}

func TestDarwinLogPredicateCarriesTheFilters(t *testing.T) {
	got := DarwinLogPredicate(protocol.JournalQueryData{Priority: "err", Unit: "WiFiManager", Search: `say "hi" \ now`})
	want := `eventType == logEvent AND (messageType == error OR messageType == fault) AND (subsystem CONTAINS[c] "wifimanager" OR process CONTAINS[c] "wifimanager") AND eventMessage CONTAINS[c] "say \"hi\" \\ now"`
	if got != want {
		t.Fatalf("predicate\n got %s\nwant %s", got, want)
	}
	if DarwinLogPredicate(protocol.JournalQueryData{Priority: "info"}) != "eventType == logEvent" {
		t.Fatal("info priority must not filter message types")
	}
}
