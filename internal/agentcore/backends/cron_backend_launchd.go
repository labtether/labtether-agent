package backends

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const launchdPlistCommandTimeout = 5 * time.Second

// DarwinCronBackend implements CronBackend using launchd and crontabs.
type DarwinCronBackend struct{}

// ListEntries lists launchd entries and crontab entries.
func (DarwinCronBackend) ListEntries() ([]protocol.CronEntry, error) {
	entries := make([]protocol.CronEntry, 0)
	var collectionErrors []error

	launchdEntries, launchdErr := collectLaunchdEntries()
	entries = append(entries, launchdEntries...)
	if launchdErr != nil {
		collectionErrors = append(collectionErrors, fmt.Errorf("launchd: %w", launchdErr))
	}

	crontabEntries, crontabErr := CollectCrontabs()
	entries = append(entries, crontabEntries...)
	if crontabErr != nil {
		collectionErrors = append(collectionErrors, fmt.Errorf("crontabs: %w", crontabErr))
	}

	return entries, combineScheduleErrors(collectionErrors...)
}

func collectLaunchdEntries() ([]protocol.CronEntry, error) {
	if _, err := exec.LookPath("plutil"); err != nil {
		return nil, fmt.Errorf("plutil is not available on this host")
	}

	currentUser := strings.TrimSpace(os.Getenv("USER"))
	homeDir, _ := os.UserHomeDir()
	directories := []struct {
		path string
		user string
	}{
		{path: "/System/Library/LaunchDaemons", user: "root"},
		{path: "/Library/LaunchDaemons", user: "root"},
		{path: "/Library/LaunchAgents", user: currentUser},
	}
	if strings.TrimSpace(homeDir) != "" {
		directories = append(directories, struct {
			path string
			user string
		}{
			path: filepath.Join(homeDir, "Library", "LaunchAgents"),
			user: currentUser,
		})
	}

	entries := make([]protocol.CronEntry, 0)
	var firstErr error
	readableDirectories := 0
	var directoryFailures []error
	var missingDirectories []error
	for _, directory := range directories {
		dirEntries, err := os.ReadDir(directory.path)
		if err != nil {
			wrapped := fmt.Errorf("read launchd directory %s: %w", directory.path, err)
			if os.IsNotExist(err) {
				missingDirectories = append(missingDirectories, wrapped)
			} else {
				directoryFailures = append(directoryFailures, wrapped)
			}
			continue
		}
		readableDirectories++
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				continue
			}
			if !strings.HasSuffix(strings.ToLower(dirEntry.Name()), ".plist") {
				continue
			}

			path := filepath.Join(directory.path, dirEntry.Name())
			entry, ok, parseErr := parseLaunchdPlist(path, directory.user)
			if parseErr != nil {
				if firstErr == nil {
					firstErr = parseErr
				}
				continue
			}
			if !ok {
				continue
			}
			entries = append(entries, entry)
		}
	}

	if readableDirectories == 0 {
		allFailures := append(append([]error{}, directoryFailures...), missingDirectories...)
		if len(allFailures) == 0 {
			return entries, fmt.Errorf("no configured launchd source is readable")
		}
		return entries, fmt.Errorf("no configured launchd source is readable: %w", combineScheduleErrors(allFailures...))
	}
	if firstErr != nil {
		directoryFailures = append(directoryFailures, firstErr)
	}
	if len(directoryFailures) > 0 {
		return entries, fmt.Errorf("some launchd sources could not be read: %w", combineScheduleErrors(directoryFailures...))
	}

	return entries, nil
}

func parseLaunchdPlist(path, user string) (protocol.CronEntry, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), launchdPlistCommandTimeout)
	defer cancel()

	out, err := securityruntime.CommandContextCombinedOutput(ctx, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return protocol.CronEntry{}, false, fmt.Errorf("launchd plist parse timed out: %s", path)
		}
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return protocol.CronEntry{}, false, fmt.Errorf("launchd plist parse failed for %s: %s", path, trimmed)
		}
		return protocol.CronEntry{}, false, fmt.Errorf("launchd plist parse failed for %s: %w", path, err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		return protocol.CronEntry{}, false, fmt.Errorf("launchd plist JSON decode failed for %s: %w", path, err)
	}

	entry, ok := BuildLaunchdCronEntry(payload, user)
	return entry, ok, nil
}

// BuildLaunchdCronEntry builds a CronEntry from a launchd plist payload.
func BuildLaunchdCronEntry(payload map[string]any, user string) (protocol.CronEntry, bool) {
	label := strings.TrimSpace(asLaunchdString(payload["Label"]))
	command := buildLaunchdCommand(payload)
	if label == "" && command == "" {
		return protocol.CronEntry{}, false
	}
	if command == "" {
		command = label
	}
	if strings.TrimSpace(user) == "" {
		user = "unknown"
	}
	schedule := BuildLaunchdSchedule(payload)
	if schedule == "" {
		schedule = "on-demand"
	}
	return protocol.CronEntry{
		Source:   "launchd",
		Schedule: schedule,
		Command:  command,
		User:     strings.TrimSpace(user),
	}, true
}

func buildLaunchdCommand(payload map[string]any) string {
	if args, ok := payload["ProgramArguments"].([]any); ok && len(args) > 0 {
		parts := make([]string, 0, len(args))
		for _, arg := range args {
			value := strings.TrimSpace(asLaunchdString(arg))
			if value == "" {
				continue
			}
			parts = append(parts, value)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	return strings.TrimSpace(asLaunchdString(payload["Program"]))
}

// BuildLaunchdSchedule builds the schedule string from a launchd plist payload.
func BuildLaunchdSchedule(payload map[string]any) string {
	parts := make([]string, 0, 3)

	if interval, ok := asLaunchdInt(payload["StartInterval"]); ok && interval > 0 {
		parts = append(parts, fmt.Sprintf("every %ds", interval))
	}

	if calendarRaw, ok := payload["StartCalendarInterval"]; ok {
		if calendar := buildLaunchdCalendarSchedule(calendarRaw); calendar != "" {
			parts = append(parts, calendar)
		}
	}

	if runAtLoad, ok := payload["RunAtLoad"].(bool); ok && runAtLoad {
		parts = append(parts, "@reboot")
	}

	return strings.Join(parts, " | ")
}

func buildLaunchdCalendarSchedule(raw any) string {
	switch value := raw.(type) {
	case map[string]any:
		return launchdCalendarMapToCron(value)
	case []any:
		calendars := make([]string, 0, len(value))
		for _, item := range value {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			cron := launchdCalendarMapToCron(itemMap)
			if cron != "" {
				calendars = append(calendars, cron)
			}
		}
		if len(calendars) == 0 {
			return ""
		}
		return strings.Join(calendars, " | ")
	default:
		return ""
	}
}

func launchdCalendarMapToCron(value map[string]any) string {
	minute := launchdCronField(value, "Minute")
	hour := launchdCronField(value, "Hour")
	day := launchdCronField(value, "Day")
	month := launchdCronField(value, "Month")
	weekday := launchdCronField(value, "Weekday")
	return strings.Join([]string{minute, hour, day, month, weekday}, " ")
}

func launchdCronField(value map[string]any, key string) string {
	if parsed, ok := asLaunchdInt(value[key]); ok {
		return strconv.Itoa(parsed)
	}
	return "*"
}

func asLaunchdInt(value any) (int, bool) {
	switch parsed := value.(type) {
	case int:
		return parsed, true
	case int32:
		return int(parsed), true
	case int64:
		return int(parsed), true
	case float64:
		return int(parsed), true
	case float32:
		return int(parsed), true
	case json.Number:
		n, err := strconv.Atoi(parsed.String())
		return n, err == nil
	default:
		return 0, false
	}
}

func asLaunchdString(value any) string {
	switch parsed := value.(type) {
	case string:
		return parsed
	case []byte:
		return string(parsed)
	case fmt.Stringer:
		return parsed.String()
	default:
		return ""
	}
}
