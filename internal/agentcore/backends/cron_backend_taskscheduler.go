package backends

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const (
	powershellTaskQueryTimeout = 5 * time.Second
	schtasksSummaryTimeout     = 4 * time.Second
	maxWindowsCronEntries      = 10000
)

// windowsTaskSchedulerInventoryScript is deliberately fixed: no request data is
// interpolated into it. Get-ScheduledTask is materially faster than the verbose
// schtasks CSV query on real Windows hosts while still exposing the fields the
// protocol promises.
const windowsTaskSchedulerInventoryScript = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Format-LabTetherTaskTime($value) {
    if ($null -eq $value -or ([DateTime]$value) -eq [DateTime]::MinValue) { return '' }
    return ([DateTime]$value).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}
$rows = @(Get-ScheduledTask -ErrorAction Stop |
    Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    ForEach-Object {
        $task = $_
        $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop
        $triggerDescriptions = @($task.Triggers | ForEach-Object {
            $className = [string]$_.CimClass.CimClassName
            $kind = $className -replace '^MSFT_Task', '' -replace 'Trigger$', ''
            if ([string]::IsNullOrWhiteSpace($kind)) { $kind = 'scheduled' }
            $start = [string]$_.StartBoundary
            if ([string]::IsNullOrWhiteSpace($start)) { $kind.ToLowerInvariant() }
            else { ('{0} at {1}' -f $kind.ToLowerInvariant(), $start) }
        })
        $schedule = if ($triggerDescriptions.Count -eq 0) { 'on-demand' } else { $triggerDescriptions -join '; ' }
        [pscustomobject]@{
            source = 'task-scheduler'
            schedule = $schedule
            command = ('{0}{1}' -f $task.TaskPath, $task.TaskName)
            user = [string]$task.Principal.UserId
            next_run = Format-LabTetherTaskTime $info.NextRunTime
            last_run = Format-LabTetherTaskTime $info.LastRunTime
        }
    })
[Console]::Out.Write((ConvertTo-Json -InputObject $rows -Compress -Depth 4))`

// RunSchtasksCommand is the function used to execute schtasks.exe. Overridable for tests.
var RunSchtasksCommand = securityruntime.CommandContextCombinedOutput

// WindowsCronBackend implements CronBackend using Windows Task Scheduler.
// It has no build tags so that parser tests can run on any platform.
type WindowsCronBackend struct{}

// ListEntries lists non-Microsoft scheduled tasks. It uses the TaskScheduler
// PowerShell cmdlets first, then a bounded non-verbose schtasks summary as a
// compatibility fallback. The verbose schtasks query routinely exceeds the
// hub's request deadline on otherwise healthy Windows hosts.
func (WindowsCronBackend) ListEntries() ([]protocol.CronEntry, error) {
	entries, primaryErr := listTasksWithPowerShell()
	if primaryErr == nil {
		return entries, nil
	}

	entries, fallbackErr := listTasksWithSchtasksSummary()
	if fallbackErr == nil {
		return entries, nil
	}
	return nil, fmt.Errorf("Task Scheduler inventory failed (PowerShell: %v; schtasks fallback: %v)", primaryErr, fallbackErr)
}

func listTasksWithPowerShell() ([]protocol.CronEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), powershellTaskQueryTimeout)
	defer cancel()

	out, err := RunSchtasksCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsTaskSchedulerInventoryScript)
	if err != nil {
		return nil, windowsTaskCommandError(ctx, "PowerShell Task Scheduler query", out, err)
	}
	return parsePowerShellTaskInventory(out)
}

func listTasksWithSchtasksSummary() ([]protocol.CronEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), schtasksSummaryTimeout)
	defer cancel()

	out, err := RunSchtasksCommand(ctx, "schtasks.exe", "/Query", "/FO", "CSV", "/NH")
	if err != nil {
		return nil, windowsTaskCommandError(ctx, "schtasks summary query", out, err)
	}
	return parseSchtasksSummaryCSV(out)
}

func windowsTaskCommandError(ctx context.Context, operation string, out []byte, err error) error {
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timed out", operation)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed != "" {
		return fmt.Errorf("%s failed: %s", operation, trimmed)
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

func parsePowerShellTaskInventory(raw []byte) ([]protocol.CronEntry, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("PowerShell Task Scheduler query returned empty output")
	}

	var entries []protocol.CronEntry
	if trimmed[0] == '{' {
		var single protocol.CronEntry
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, fmt.Errorf("parse PowerShell Task Scheduler object: %w", err)
		}
		entries = []protocol.CronEntry{single}
	} else if err := json.Unmarshal(trimmed, &entries); err != nil {
		return nil, fmt.Errorf("parse PowerShell Task Scheduler array: %w", err)
	}

	if len(entries) > maxWindowsCronEntries {
		return nil, fmt.Errorf("PowerShell Task Scheduler query returned too many entries: %d", len(entries))
	}
	for i := range entries {
		entry := &entries[i]
		entry.Source = strings.TrimSpace(entry.Source)
		entry.Schedule = strings.TrimSpace(entry.Schedule)
		entry.Command = strings.TrimSpace(entry.Command)
		entry.User = strings.TrimSpace(entry.User)
		if entry.Source != "task-scheduler" {
			return nil, fmt.Errorf("PowerShell Task Scheduler entry %d has invalid source %q", i, entry.Source)
		}
		if entry.Schedule == "" || entry.Command == "" {
			return nil, fmt.Errorf("PowerShell Task Scheduler entry %d is missing schedule or command", i)
		}
		for field, value := range map[string]*string{"next_run": &entry.NextRun, "last_run": &entry.LastRun} {
			if *value == "" {
				continue
			}
			parsed, err := time.Parse(time.RFC3339Nano, *value)
			if err != nil {
				return nil, fmt.Errorf("PowerShell Task Scheduler entry %d has invalid %s: %w", i, field, err)
			}
			*value = parsed.UTC().Format(time.RFC3339)
		}
	}
	return entries, nil
}

// parseSchtasksSummaryCSV parses the fast three-column output of
// `schtasks.exe /Query /FO CSV /NH`. It intentionally reports only what this
// format can prove and deduplicates tasks that schtasks repeats per trigger.
func parseSchtasksSummaryCSV(raw []byte) ([]protocol.CronEntry, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	r := csv.NewReader(bytes.NewReader(raw))
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("schtasks summary CSV parse failed: %w", err)
	}

	seen := make(map[string]struct{}, len(records))
	entries := make([]protocol.CronEntry, 0, len(records))
	for _, row := range records {
		if len(row) < 1 {
			continue
		}
		name := strings.TrimSpace(row[0])
		if name == "" || strings.HasPrefix(name, `\Microsoft\`) {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		rawNext := ""
		if len(row) > 1 {
			rawNext = strings.TrimSpace(row[1])
		}
		schedule := "on-demand"
		if rawNext != "" && !strings.EqualFold(rawNext, "N/A") {
			schedule = "scheduled (details unavailable)"
		}
		entries = append(entries, protocol.CronEntry{
			Source:   "task-scheduler",
			Schedule: schedule,
			Command:  name,
			NextRun:  parseUnambiguousSchtasksSummaryTime(rawNext),
		})
		if len(entries) > maxWindowsCronEntries {
			return nil, fmt.Errorf("schtasks summary returned too many entries")
		}
	}
	return entries, nil
}

func parseUnambiguousSchtasksSummaryTime(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "N/A") {
		return ""
	}
	dateAndTime := strings.Fields(value)
	if len(dateAndTime) < 2 {
		return ""
	}
	dateParts := strings.Split(dateAndTime[0], "/")
	if len(dateParts) != 3 {
		return ""
	}
	first, firstErr := time.Parse("2", dateParts[0])
	second, secondErr := time.Parse("2", dateParts[1])
	if firstErr != nil || secondErr != nil {
		return ""
	}
	var layouts []string
	if first.Day() > 12 {
		layouts = []string{"2/1/2006 3:04:05 PM", "2/1/2006 15:04:05"}
	} else if second.Day() > 12 {
		layouts = []string{"1/2/2006 3:04:05 PM", "1/2/2006 15:04:05"}
	} else {
		// Without the host locale, 1/2 and 2/1 cannot be distinguished safely.
		return ""
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// parseSchtasksCSV parses the CSV output of `schtasks.exe /Query /FO CSV /V`.
//
// The output has a header row followed by one row per task. Tasks whose
// TaskName starts with \Microsoft\ are filtered out as OS maintenance tasks.
func parseSchtasksCSV(raw []byte) ([]protocol.CronEntry, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}

	r := csv.NewReader(bytes.NewReader(raw))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true

	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("schtasks CSV parse failed: %w", err)
	}
	if len(records) < 2 {
		// Header only or empty — no tasks.
		return nil, nil
	}

	// Build a column index from the header row.
	header := records[0]
	colIndex := make(map[string]int, len(header))
	for i, h := range header {
		colIndex[strings.TrimSpace(h)] = i
	}

	col := func(row []string, name string) string {
		i, ok := colIndex[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	var entries []protocol.CronEntry
	for _, row := range records[1:] {
		taskName := col(row, "TaskName")
		if taskName == "" {
			continue
		}
		// Filter OS maintenance tasks under \Microsoft\.
		if strings.HasPrefix(taskName, `\Microsoft\`) {
			continue
		}

		schedType := col(row, "Schedule Type")
		startTime := col(row, "Start Time")
		schedule := buildSchtasksSchedule(schedType, startTime)

		nextRun := parseSchtasksTime(col(row, "Next Run Time"))
		lastRun := parseSchtasksTime(col(row, "Last Run Time"))

		// Run As User may be a qualified "HOST\user" form; strip the host prefix.
		user := col(row, "Run As User")
		if idx := strings.LastIndex(user, `\`); idx >= 0 {
			user = user[idx+1:]
		}

		entries = append(entries, protocol.CronEntry{
			Source:   "task-scheduler",
			Schedule: schedule,
			Command:  taskName,
			User:     user,
			NextRun:  nextRun,
			LastRun:  lastRun,
		})
	}

	return entries, nil
}

// buildSchtasksSchedule constructs a human-readable schedule expression from
// the Schedule Type and Start Time columns of schtasks CSV output.
func buildSchtasksSchedule(schedType, startTime string) string {
	parts := make([]string, 0, 2)
	if schedType != "" && schedType != "Scheduling data is not available in this format." {
		parts = append(parts, schedType)
	}
	if startTime != "" && startTime != "N/A" {
		parts = append(parts, "at "+startTime)
	}
	if len(parts) == 0 {
		return "on-demand"
	}
	return strings.Join(parts, " ")
}

// schtasksTimeLayouts lists the date/time formats schtasks.exe may produce.
// schtasks emits locale-dependent timestamps; we cover the common US en-US format.
var schtasksTimeLayouts = []string{
	"1/2/2006 3:04:05 PM",
	"1/2/2006 3:04:05 AM",
	"1/2/2006 15:04:05",
}

// parseSchtasksTime converts a schtasks timestamp string to RFC3339.
// Returns empty string if the value is "N/A", empty, or unparseable.
func parseSchtasksTime(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" || strings.EqualFold(v, "N/A") {
		return ""
	}
	for _, layout := range schtasksTimeLayouts {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	// Return empty rather than a misleading value if we cannot parse.
	return ""
}
