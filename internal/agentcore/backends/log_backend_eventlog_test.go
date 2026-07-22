package backends

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestParseWevtutilOutputCount(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "wevtutil_query.json"))
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	entries, err := parseWevtutilOutput(raw)
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error: %v", err)
	}

	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}

func TestParseWevtutilOutputFields(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "wevtutil_query.json"))
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	entries, err := parseWevtutilOutput(raw)
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error: %v", err)
	}

	// First entry: Level 4 (info), Service Control Manager
	first := entries[0]
	if first.Message == "" {
		t.Fatal("expected non-empty message on first entry")
	}
	if !strings.Contains(first.Message, "Windows Update service") {
		t.Fatalf("message=%q, expected to contain 'Windows Update service'", first.Message)
	}
	if first.Level != "info" {
		t.Fatalf("level=%q, want info (level 4)", first.Level)
	}
	if first.Source != "Service Control Manager" {
		t.Fatalf("source=%q, want 'Service Control Manager'", first.Source)
	}
	if first.Timestamp == "" {
		t.Fatal("expected timestamp to be set")
	}
	// Timestamp should be RFC3339
	if !strings.Contains(first.Timestamp, "T") {
		t.Fatalf("timestamp=%q does not look like RFC3339", first.Timestamp)
	}
}

func TestParseWevtutilOutputLevelMapping(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "wevtutil_query.json"))
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	entries, err := parseWevtutilOutput(raw)
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error: %v", err)
	}

	// Build a map by Source+level for assertions.
	// entry[0]: Level 4 -> info  (Service Control Manager)
	// entry[1]: Level 0 -> info  (Security Auditing - 0 means success/info)
	// entry[2]: Level 1 -> critical (Kernel-Power)
	// entry[3]: Level 2 -> error  (WindowsUpdateClient)
	// entry[4]: Level 3 -> warning (Dhcp-Client)
	expected := []struct {
		levelNum  int
		wantLevel string
	}{
		{4, "info"},
		{0, "info"},
		{1, "critical"},
		{2, "error"},
		{3, "warning"},
	}

	for i, ex := range expected {
		if i >= len(entries) {
			t.Fatalf("entry[%d] not present", i)
		}
		if entries[i].Level != ex.wantLevel {
			t.Errorf("entry[%d] level=%q, want %q (numeric level %d)", i, entries[i].Level, ex.wantLevel, ex.levelNum)
		}
	}
}

func TestParseWevtutilOutputSources(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "wevtutil_query.json"))
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	entries, err := parseWevtutilOutput(raw)
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error: %v", err)
	}

	wantSources := []string{
		"Service Control Manager",
		"Microsoft-Windows-Security-Auditing",
		"Microsoft-Windows-Kernel-Power",
		"Microsoft-Windows-WindowsUpdateClient",
		"Microsoft-Windows-Dhcp-Client",
	}

	for i, want := range wantSources {
		if i >= len(entries) {
			t.Fatalf("entry[%d] not present", i)
		}
		if entries[i].Source != want {
			t.Errorf("entry[%d] source=%q, want %q", i, entries[i].Source, want)
		}
	}
}

func TestParseWevtutilOutputEmpty(t *testing.T) {
	t.Parallel()

	entries, err := parseWevtutilOutput([]byte(""))
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error on empty input: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries from empty input, got %d", len(entries))
	}
}

func TestParseWevtutilRenderedXML(t *testing.T) {
	t.Parallel()

	raw := []byte(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><Level>4</Level><TimeCreated SystemTime='2026-07-14T00:14:46.1362000Z'/></System><RenderingInfo Culture='en-AU'><Message>The LabTether QA service entered the running state.</Message></RenderingInfo></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power'/><Level>2</Level><TimeCreated SystemTime='2026-07-14T00:13:00.0000000Z'/></System><RenderingInfo Culture='en-AU'><Message>Fixture error.</Message></RenderingInfo></Event>`)
	entries, err := parseWevtutilOutput(raw)
	if err != nil {
		t.Fatalf("parseWevtutilOutput: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Source != "Service Control Manager" || entries[0].Level != "info" {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[1].Source != "Microsoft-Windows-Kernel-Power" || entries[1].Level != "error" {
		t.Fatalf("second entry = %+v", entries[1])
	}
}

func TestParseWevtutilOutputSkipsInvalidLines(t *testing.T) {
	t.Parallel()

	input := []byte(`not json
{"Event":{"System":{"Provider":{"Name":"TestProvider"},"Level":"4","TimeCreated":{"SystemTime":"2026-03-21T08:00:00.000000000Z"}},"RenderingInfo":{"Message":"hello world","Level":"Information"}}}
also not json
`)
	entries, err := parseWevtutilOutput(input)
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
	if entries[0].Message != "hello world" {
		t.Fatalf("message=%q, want 'hello world'", entries[0].Message)
	}
}

func TestParseWevtutilOutputSkipsEmptyMessage(t *testing.T) {
	t.Parallel()

	// An event with an empty message should be skipped.
	input := []byte(`{"Event":{"System":{"Provider":{"Name":"TestProvider"},"Level":"4","TimeCreated":{"SystemTime":"2026-03-21T08:00:00.000000000Z"}},"RenderingInfo":{"Message":"","Level":"Information"}}}`)
	entries, err := parseWevtutilOutput(input)
	if err != nil {
		t.Fatalf("parseWevtutilOutput returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries from event with empty message, got %d", len(entries))
	}
}

func TestBuildWevtutilQueryArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		req      protocol.JournalQueryData
		channel  string
		wantArgs []string
	}{
		{
			name:     "basic-system-channel",
			req:      protocol.JournalQueryData{Limit: 50},
			channel:  "System",
			wantArgs: []string{"qe", "System", "/f:RenderedXml", "/rd:true", "/c:50"},
		},
		{
			name:     "with-since",
			req:      protocol.JournalQueryData{Limit: 10, Since: "2026-03-21T00:00:00Z"},
			channel:  "Application",
			wantArgs: []string{"qe", "Application", "/f:RenderedXml", "/rd:true", "/c:10", "/q:*[System[TimeCreated[@SystemTime>='2026-03-21T00:00:00Z']]]"},
		},
		{
			name:    "with-time-range",
			req:     protocol.JournalQueryData{Limit: 10, Since: "2026-03-21T00:00:00Z", Until: "2026-03-21T01:00:00Z"},
			channel: "System",
			wantArgs: []string{
				"qe", "System", "/f:RenderedXml", "/rd:true", "/c:10",
				"/q:*[System[TimeCreated[@SystemTime>='2026-03-21T00:00:00Z' and @SystemTime<='2026-03-21T01:00:00Z']]]",
			},
		},
		{
			name:     "default-limit",
			req:      protocol.JournalQueryData{Limit: 0},
			channel:  "System",
			wantArgs: []string{"qe", "System", "/f:RenderedXml", "/rd:true", "/c:200"},
		},
		{
			name:     "clamped-limit",
			req:      protocol.JournalQueryData{Limit: 9999},
			channel:  "System",
			wantArgs: []string{"qe", "System", "/f:RenderedXml", "/rd:true", "/c:1000"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := BuildWevtutilQueryArgs(tc.req, tc.channel)
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("args=%v, want %v", args, tc.wantArgs)
			}
			for i, want := range tc.wantArgs {
				if args[i] != want {
					t.Errorf("args[%d]=%q, want %q", i, args[i], want)
				}
			}
		})
	}
}

func TestNormalizeWindowsJournalQueryTimes(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)

	got, err := normalizeWindowsJournalQueryTimes(protocol.JournalQueryData{
		Since: "1h ago",
		Until: "now",
	}, now)
	if err != nil {
		t.Fatalf("normalizeWindowsJournalQueryTimes: %v", err)
	}
	if got.Since != "2026-07-14T00:00:00Z" || got.Until != "2026-07-14T01:00:00Z" {
		t.Fatalf("normalized range = (%q, %q)", got.Since, got.Until)
	}

	if _, err := normalizeWindowsJournalQueryTimes(protocol.JournalQueryData{Since: "tomorrow-ish"}, now); err == nil {
		t.Fatal("expected an unsupported time to be rejected")
	}
	if _, err := normalizeWindowsJournalQueryTimes(protocol.JournalQueryData{
		Since: "2026-07-14T02:00:00Z",
		Until: "2026-07-14T01:00:00Z",
	}, now); err == nil {
		t.Fatal("expected a reversed time range to be rejected")
	}
}

func TestWindowsLogBackendReturnsErrorWhenEveryChannelFails(t *testing.T) {
	original := RunWevtutilCommand
	t.Cleanup(func() { RunWevtutilCommand = original })
	RunWevtutilCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Invalid value for option f."), nil
	}

	entries, err := (WindowsLogBackend{}).QueryEntries(protocol.JournalQueryData{Limit: 5})
	if err == nil {
		t.Fatalf("QueryEntries returned entries=%v without reporting total channel failure", entries)
	}
	if !strings.Contains(err.Error(), "all Windows Event Log channel queries failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveWindowsLogUnitFilter(t *testing.T) {
	channels := []string{"System", "Application"}

	channel, source := resolveWindowsLogUnitFilter(channels, "system")
	if channel != "System" || source != "" {
		t.Fatalf("channel filter = (%q, %q), want (System, empty)", channel, source)
	}

	channel, source = resolveWindowsLogUnitFilter(channels, "Service Control Manager")
	if channel != "" || source != "Service Control Manager" {
		t.Fatalf("source filter = (%q, %q), want (empty, Service Control Manager)", channel, source)
	}
}

func TestWevtutilLevelToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level int
		want  string
	}{
		{0, "info"},
		{1, "critical"},
		{2, "error"},
		{3, "warning"},
		{4, "info"},
		{5, "info"},
		{99, "info"},
	}

	for _, tc := range tests {
		got := wevtutilLevelToString(tc.level)
		if got != tc.want {
			t.Errorf("wevtutilLevelToString(%d)=%q, want %q", tc.level, got, tc.want)
		}
	}
}
