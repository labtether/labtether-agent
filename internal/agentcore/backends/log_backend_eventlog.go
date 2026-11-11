package backends

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const (
	wevtutilQueryCommandTimeout = 20 * time.Second
	wevtutilDefaultChannels     = "System,Application"
)

// wevtutilStreamPollInterval is how often the stream asks for new events.
// A variable so tests can shorten it.
var wevtutilStreamPollInterval = 5 * time.Second

var windowsRelativeLogTimePattern = regexp.MustCompile(`(?i)^([0-9]+)\s*([smhdw])(?:\s+ago)?$`)

// WindowsLogBackend implements LogBackend using wevtutil on Windows.
// It has no build tags so that parser tests can run on any platform.
type WindowsLogBackend struct {
	// Channels is the comma-separated list of Event Log channels to query.
	// Defaults to "System,Application" if empty.
	Channels string
}

// RunWevtutilCommand is the function used to execute wevtutil. Overridable for tests.
var RunWevtutilCommand = securityruntime.CommandContextCombinedOutput

// QueryEntries queries Windows Event Log entries via wevtutil across configured channels.
func (b WindowsLogBackend) QueryEntries(req protocol.JournalQueryData) ([]protocol.LogStreamData, error) {
	var err error
	req, err = normalizeWindowsJournalQueryTimes(req, time.Now())
	if err != nil {
		return nil, err
	}
	channels := b.resolvedChannels()
	channelFilter, sourceFilter := resolveWindowsLogUnitFilter(channels, req.Unit)
	filterReq := req
	filterReq.Unit = sourceFilter

	limit := NormalizedJournalLimit(req.Limit)
	perChannel := limit
	if sourceFilter != "" || strings.TrimSpace(req.Search) != "" {
		// Source and text filters run on the events read here, so read as
		// many as a query may; the level filter is part of the query itself.
		perChannel = NormalizedJournalLimit(maxJournalQueryLimit)
	}

	var all []protocol.LogStreamData
	var channelErrors []error
	attemptedChannels := 0
	successfulChannels := 0
	for _, ch := range channels {
		if channelFilter != "" && !strings.EqualFold(ch, channelFilter) {
			continue
		}

		attemptedChannels++
		entries, err := b.queryChannel(req, ch, perChannel)
		if err != nil {
			// A channel can be unavailable or access-controlled. Preserve useful
			// results from other channels, but do not turn total backend failure
			// into a misleading successful empty response.
			channelErrors = append(channelErrors, err)
			continue
		}
		successfulChannels++
		all = append(all, entries...)
	}
	if attemptedChannels > 0 && successfulChannels == 0 {
		return nil, fmt.Errorf("all Windows Event Log channel queries failed: %w", errors.Join(channelErrors...))
	}

	// Apply search filter and trim to limit.
	filtered := make([]protocol.LogStreamData, 0, len(all))
	for _, e := range all {
		if EntryMatchesQuery(e, filterReq) {
			filtered = append(filtered, e)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].Timestamp > filtered[j].Timestamp
	})
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return filtered, nil
}

func normalizeWindowsJournalQueryTimes(req protocol.JournalQueryData, now time.Time) (protocol.JournalQueryData, error) {
	since, err := normalizeWindowsEventLogTime(req.Since, now)
	if err != nil {
		return req, fmt.Errorf("invalid since time: %w", err)
	}
	until, err := normalizeWindowsEventLogTime(req.Until, now)
	if err != nil {
		return req, fmt.Errorf("invalid until time: %w", err)
	}
	if since != "" && until != "" {
		sinceTime, _ := time.Parse(time.RFC3339Nano, since)
		untilTime, _ := time.Parse(time.RFC3339Nano, until)
		if sinceTime.After(untilTime) {
			return req, errors.New("since time must not be after until time")
		}
	}
	req.Since = since
	req.Until = until
	return req, nil
}

func normalizeWindowsEventLogTime(raw string, now time.Time) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.EqualFold(value, "now") {
		return now.UTC().Format(time.RFC3339Nano), nil
	}
	if match := windowsRelativeLogTimePattern.FindStringSubmatch(value); len(match) == 3 {
		amount, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid relative time %q", value)
		}
		unit := map[string]time.Duration{
			"s": time.Second,
			"m": time.Minute,
			"h": time.Hour,
			"d": 24 * time.Hour,
			"w": 7 * 24 * time.Hour,
		}[strings.ToLower(match[2])]
		const maxDuration = time.Duration(1<<63 - 1)
		if unit <= 0 || time.Duration(amount) > maxDuration/unit {
			return "", fmt.Errorf("relative time %q is out of range", value)
		}
		return now.Add(-time.Duration(amount) * unit).UTC().Format(time.RFC3339Nano), nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano), nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), nil
		}
	}
	return "", fmt.Errorf("unsupported time %q", value)
}

// resolveWindowsLogUnitFilter accepts either a Windows Event Log channel or a
// provider/source name in the protocol's cross-platform Unit field.
func resolveWindowsLogUnitFilter(channels []string, raw string) (channel, source string) {
	unit := strings.TrimSpace(raw)
	if unit == "" {
		return "", ""
	}
	for _, candidate := range channels {
		if strings.EqualFold(candidate, unit) {
			return candidate, ""
		}
	}
	return "", unit
}

func (b WindowsLogBackend) resolvedChannels() []string {
	raw := strings.TrimSpace(b.Channels)
	if raw == "" {
		raw = wevtutilDefaultChannels
	}
	parts := strings.Split(raw, ",")
	channels := make([]string, 0, len(parts))
	for _, p := range parts {
		ch := strings.TrimSpace(p)
		if ch != "" {
			channels = append(channels, ch)
		}
	}
	if len(channels) == 0 {
		return []string{"System", "Application"}
	}
	return channels
}

func (b WindowsLogBackend) queryChannel(req protocol.JournalQueryData, channel string, limit int) ([]protocol.LogStreamData, error) {
	overrideReq := req
	overrideReq.Limit = limit

	ctx, cancel := context.WithTimeout(context.Background(), wevtutilQueryCommandTimeout)
	defer cancel()

	args := BuildWevtutilQueryArgs(overrideReq, channel)
	out, err := RunWevtutilCommand(ctx, "wevtutil", args...)
	out = decodeWevtutilOutput(out)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("wevtutil query timed out for channel %s", channel)
		}
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return nil, fmt.Errorf("wevtutil query failed for channel %s: %s", channel, trimmed)
		}
		return nil, fmt.Errorf("wevtutil query failed for channel %s: %w", channel, err)
	}

	return parseWevtutilOutput(out)
}

// BuildWevtutilQueryArgs builds the argument list for a wevtutil qe command.
func BuildWevtutilQueryArgs(req protocol.JournalQueryData, channel string) []string {
	limit := NormalizedJournalLimit(req.Limit)
	args := []string{
		"qe", channel,
		"/f:RenderedXml",
		"/rd:true",
		"/c:" + strconv.Itoa(limit),
		wevtutilUnicodeArg,
	}
	var times []string
	if since := strings.TrimSpace(req.Since); since != "" {
		times = append(times, "@SystemTime>='"+since+"'")
	}
	if until := strings.TrimSpace(req.Until); until != "" {
		times = append(times, "@SystemTime<='"+until+"'")
	}
	var conditions []string
	if levels := wevtutilLevelCondition(req.Priority); levels != "" {
		conditions = append(conditions, levels)
	}
	if len(times) > 0 {
		conditions = append(conditions, "TimeCreated["+strings.Join(times, " and ")+"]")
	}
	if len(conditions) > 0 {
		args = append(args, "/q:*[System["+strings.Join(conditions, " and ")+"]]")
	}
	return args
}

// maxJournalQueryLimit is the most events one query returns.
const maxJournalQueryLimit = 1000

// wevtutilLevelCondition turns a journal priority into Event Log levels
// (1 critical, 2 error, 3 warning), so "errors only" searches the whole log
// instead of filtering the newest events read. Priorities that include
// information events need no condition.
func wevtutilLevelCondition(priority string) string {
	maxRank, ok := priorityMaxRank(strings.ToLower(strings.TrimSpace(priority)))
	switch {
	case !ok || maxRank >= 6:
		return ""
	case maxRank <= 3:
		return "(Level=1 or Level=2)"
	default:
		return "(Level=1 or Level=2 or Level=3)"
	}
}

// wevtutilEvent is retained for compatibility with older fixtures and custom
// wrappers that convert Event Log XML to newline-delimited JSON.
type wevtutilEvent struct {
	Event struct {
		System struct {
			Provider struct {
				Name string `json:"Name"`
			} `json:"Provider"`
			Level       string `json:"Level"`
			TimeCreated struct {
				SystemTime string `json:"SystemTime"`
			} `json:"TimeCreated"`
		} `json:"System"`
		RenderingInfo struct {
			Message string `json:"Message"`
			Level   string `json:"Level"`
		} `json:"RenderingInfo"`
	} `json:"Event"`
}

type wevtutilXMLEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Level         string `xml:"Level"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	RenderingInfo struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

// parseWevtutilOutput parses the supported wevtutil RenderedXml output. A JSON
// fallback keeps compatibility with older wrappers and recorded fixtures.
func parseWevtutilOutput(raw []byte) ([]protocol.LogStreamData, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if bytes.HasPrefix(trimmed, []byte("<")) {
		return parseWevtutilRenderedXML(trimmed)
	}
	return parseWevtutilJSON(trimmed)
}

func parseWevtutilJSON(raw []byte) ([]protocol.LogStreamData, error) {
	var entries []protocol.LogStreamData
	validEvents := 0

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(nil, 256*1024) // Grow for long lines; keep idle streams small.
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var ev wevtutilEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// Skip malformed lines — wevtutil output may include BOM or preamble.
			continue
		}
		validEvents++

		message := strings.TrimSpace(ev.Event.RenderingInfo.Message)
		if message == "" {
			continue
		}

		source := strings.TrimSpace(ev.Event.System.Provider.Name)
		if source == "" {
			source = "eventlog"
		}

		level := wevtutilLevelToString(parseWevtutilLevelNum(ev.Event.System.Level))
		timestamp := wevtutilSystemTimeToRFC3339(ev.Event.System.TimeCreated.SystemTime)

		entries = append(entries, protocol.LogStreamData{
			Timestamp: timestamp,
			Level:     level,
			Message:   message,
			Source:    source,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse wevtutil output: %w", err)
	}
	if validEvents == 0 {
		return nil, errors.New("wevtutil output contained no usable events")
	}

	return entries, nil
}

func parseWevtutilRenderedXML(raw []byte) ([]protocol.LogStreamData, error) {
	records, err := parseWevtutilRenderedXMLRecords(raw)
	entries := make([]protocol.LogStreamData, 0, len(records))
	for _, record := range records {
		if record.entry.Message != "" {
			entries = append(entries, record.entry)
		}
	}
	if err != nil {
		return entries, err
	}
	return entries, nil
}

// wevtutilRecord is one event with its record number in its channel. Events
// without a message are kept here (their record number still moves the
// stream on) and left out of query results.
type wevtutilRecord struct {
	entry    protocol.LogStreamData
	recordID uint64
}

func parseWevtutilRenderedXMLRecords(raw []byte) ([]wevtutilRecord, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var records []wevtutilRecord
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return records, fmt.Errorf("failed to parse wevtutil RenderedXml output: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}

		var event wevtutilXMLEvent
		if err := decoder.DecodeElement(&event, &start); err != nil {
			return records, fmt.Errorf("failed to decode wevtutil Event element: %w", err)
		}
		source := strings.TrimSpace(event.System.Provider.Name)
		if source == "" {
			source = "eventlog"
		}
		records = append(records, wevtutilRecord{
			recordID: event.System.EventRecordID,
			entry: protocol.LogStreamData{
				Timestamp: wevtutilSystemTimeToRFC3339(event.System.TimeCreated.SystemTime),
				Level:     wevtutilLevelToString(parseWevtutilLevelNum(event.System.Level)),
				Message:   strings.TrimSpace(event.RenderingInfo.Message),
				Source:    source,
			},
		})
	}
	if len(records) == 0 {
		return nil, errors.New("wevtutil RenderedXml output contained no usable Event elements")
	}
	return records, nil
}

// parseWevtutilLevelNum converts the Level string from wevtutil JSON to an integer.
// Windows Event Log levels are: 0=LogAlways/Info, 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose.
func parseWevtutilLevelNum(raw string) int {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 4
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 4
	}
	return n
}

// wevtutilLevelToString maps Windows Event Log numeric levels to LabTether log level strings.
// Windows levels: 0=LogAlways(info), 1=Critical, 2=Error, 3=Warning, 4=Information, 5=Verbose(info).
func wevtutilLevelToString(level int) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	default:
		// 0 (LogAlways/success), 4 (Information), 5 (Verbose), unknown
		return "info"
	}
}

// wevtutilSystemTimeToRFC3339 converts the wevtutil SystemTime format to RFC3339.
// wevtutil emits timestamps like "2026-03-21T08:12:34.000000000Z".
func wevtutilSystemTimeToRFC3339(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}

	layouts := []string{
		"2006-01-02T15:04:05.000000000Z",
		"2006-01-02T15:04:05.000000000Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}

	return time.Now().UTC().Format(time.RFC3339)
}
