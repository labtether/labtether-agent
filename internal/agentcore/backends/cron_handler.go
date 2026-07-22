package backends

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// CronManager handles cron/timer visibility requests from the hub.
type CronManager struct {
	Backend CronBackend
}

// NewCronManager creates a CronManager with the OS-appropriate backend.
func NewCronManager() *CronManager {
	return &CronManager{
		Backend: NewCronBackendForOS(),
	}
}

// CloseAll is a no-op for CronManager — cron requests are stateless
// and require no cleanup.
func (cm *CronManager) CloseAll() {}

// HandleCronList collects cron jobs and systemd timers and sends them to the hub.
func (cm *CronManager) HandleCronList(transport MessageSender, msg protocol.Message) {
	var req protocol.CronListData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("cron: invalid cron.list request: %v", err)
		return
	}

	entries, collectErr := cm.Backend.ListEntries()
	if collectErr != nil {
		log.Printf("cron: failed to collect schedules: %v", collectErr)
	}

	var errMsg string
	if collectErr != nil {
		errMsg = collectErr.Error()
	}

	data, marshalErr := json.Marshal(protocol.CronListedData{
		RequestID: req.RequestID,
		Entries:   entries,
		Error:     errMsg,
	})
	if marshalErr != nil {
		log.Printf("cron: failed to marshal cron.listed response: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgCronListed,
		ID:   req.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("cron: failed to send cron.listed for request %s: %v", req.RequestID, sendErr)
	}
}

// CollectSystemdTimers runs `systemctl list-timers --all --no-pager --plain`
// and parses the output to extract timer entries.
func CollectSystemdTimers() ([]protocol.CronEntry, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, nil // systemd not available, skip silently
	}

	out, err := securityruntime.CaptureCombinedOutput(
		exec.Command("systemctl", "list-timers", "--all", "--no-pager", "--plain"),
		securityruntime.DefaultCommandOutputLimit,
	)
	if err != nil {
		return nil, err
	}

	var entries []protocol.CronEntry
	scanner := bufio.NewScanner(bytes.NewReader(out))
	headerSkipped := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Skip the header line and the summary line at the end.
		if !headerSkipped {
			if strings.HasPrefix(line, "NEXT") {
				headerSkipped = true
			}
			continue
		}
		// The summary line starts with a digit (e.g., "13 timers listed.")
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			break
		}

		// --plain format columns: NEXT LEFT LAST PASSED UNIT ACTIVATES
		// NEXT and LAST are multi-word timestamps (e.g., "Sun 2026-02-23 12:00:00 UTC")
		// We parse by splitting on whitespace and working with the known field count.
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// The UNIT is the second-to-last field, ACTIVATES is the last field.
		unit := fields[len(fields)-2]
		activates := fields[len(fields)-1]

		// Try to parse NEXT — first 4 fields might be the timestamp (day, date, time, tz)
		// or it could be "n/a" if no next run.
		var nextRun string
		nextStr := strings.Join(fields[:4], " ")
		if !strings.Contains(nextStr, "n/a") {
			if t, parseErr := ParseSystemdTime(nextStr); parseErr == nil {
				nextRun = t.Format(time.RFC3339)
			}
		}

		entries = append(entries, protocol.CronEntry{
			Source:   "systemd-timer",
			Schedule: unit,
			Command:  activates,
			User:     "root",
			NextRun:  nextRun,
		})
	}
	return entries, nil
}

// ParseSystemdTime attempts to parse a systemd timer timestamp like
// "Sun 2026-02-23 12:00:00 UTC".
func ParseSystemdTime(s string) (time.Time, error) {
	// Try common formats.
	layouts := []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, &CronError{"unparseable time: " + s}
}

// CronError represents a cron parsing error.
type CronError struct{ Msg string }

func (e *CronError) Error() string { return e.Msg }

// CollectCrontabs reads user crontab files and /etc/cron.d/* entries.
func CollectCrontabs() ([]protocol.CronEntry, error) {
	return CollectCrontabsFromPaths(
		[]string{"/var/spool/cron/crontabs", "/var/spool/cron"},
		"/etc/cron.d",
		"/etc/crontab",
	)
}

// CollectCrontabsFromPaths reads crontab files from the given paths.
func CollectCrontabsFromPaths(userDirs []string, cronDDir, systemCrontabPath string) ([]protocol.CronEntry, error) {
	return collectCrontabsFromPathsWithFS(userDirs, cronDDir, systemCrontabPath, os.ReadDir, os.ReadFile)
}

type cronReadDirFunc func(string) ([]os.DirEntry, error)
type cronReadFileFunc func(string) ([]byte, error)

func collectCrontabsFromPathsWithFS(
	userDirs []string,
	cronDDir,
	systemCrontabPath string,
	readDir cronReadDirFunc,
	readFile cronReadFileFunc,
) ([]protocol.CronEntry, error) {
	var entries []protocol.CronEntry
	configuredSources := 0
	readableSources := 0
	var sourceFailures []error
	var missingSources []error

	recordSourceFailure := func(kind, path string, err error) {
		wrapped := fmt.Errorf("%s %s: %w", kind, path, err)
		if os.IsNotExist(err) {
			missingSources = append(missingSources, wrapped)
			return
		}
		sourceFailures = append(sourceFailures, wrapped)
	}

	// User crontabs from /var/spool/cron/crontabs/ (Debian/Ubuntu)
	// or /var/spool/cron/ (RHEL/CentOS).
	for _, dir := range userDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		configuredSources++
		dirEntries, err := readDir(dir)
		if err != nil {
			recordSourceFailure("read user crontab directory", dir, err)
			continue
		}
		readableSources++
		for _, de := range dirEntries {
			if de.IsDir() {
				continue
			}
			user := de.Name()
			path := filepath.Join(dir, user)
			parsed, parseErr := parseCrontabFileWithReader(path, user, false, readFile)
			if parseErr != nil {
				sourceFailures = append(sourceFailures, fmt.Errorf("read user crontab %s: %w", path, parseErr))
				continue
			}
			entries = append(entries, parsed...)
		}
	}

	// System crontabs from /etc/cron.d/
	cronDDir = strings.TrimSpace(cronDDir)
	if cronDDir != "" {
		configuredSources++
		dirEntries, err := readDir(cronDDir)
		if err != nil {
			recordSourceFailure("read system crontab directory", cronDDir, err)
		} else {
			readableSources++
			for _, de := range dirEntries {
				if de.IsDir() {
					continue
				}
				path := filepath.Join(cronDDir, de.Name())
				parsed, parseErr := parseCrontabFileWithReader(path, "", true, readFile)
				if parseErr != nil {
					sourceFailures = append(sourceFailures, fmt.Errorf("read system crontab %s: %w", path, parseErr))
					continue
				}
				entries = append(entries, parsed...)
			}
		}
	}

	// System crontab from /etc/crontab
	systemCrontabPath = strings.TrimSpace(systemCrontabPath)
	if systemCrontabPath != "" {
		configuredSources++
		parsed, parseErr := parseCrontabFileWithReader(systemCrontabPath, "", true, readFile)
		if parseErr != nil {
			recordSourceFailure("read system crontab", systemCrontabPath, parseErr)
		} else {
			readableSources++
			entries = append(entries, parsed...)
		}
	}

	if configuredSources == 0 {
		return entries, errors.New("no crontab sources are configured")
	}
	if readableSources == 0 {
		allFailures := append(append([]error{}, sourceFailures...), missingSources...)
		if len(allFailures) == 0 {
			return entries, errors.New("no configured crontab source is readable")
		}
		return entries, fmt.Errorf("no configured crontab source is readable: %w", combineScheduleErrors(allFailures...))
	}
	if len(sourceFailures) > 0 {
		return entries, fmt.Errorf("some crontab sources could not be read: %w", combineScheduleErrors(sourceFailures...))
	}
	return entries, nil
}

// ParseCrontabFile reads a crontab file and extracts cron entries.
// If systemStyle is true, the 6th field is the user (as in /etc/cron.d/* files).
func ParseCrontabFile(path, defaultUser string, systemStyle bool) []protocol.CronEntry {
	entries, _ := parseCrontabFileWithReader(path, defaultUser, systemStyle, os.ReadFile)
	return entries
}

func parseCrontabFileWithReader(path, defaultUser string, systemStyle bool, readFile cronReadFileFunc) ([]protocol.CronEntry, error) {
	data, err := readFile(path) // #nosec G304 -- Path comes from enumerated cron directories under controlled system locations.
	if err != nil {
		return nil, err
	}
	return parseCrontabData(data, defaultUser, systemStyle), nil
}

func parseCrontabData(data []byte, defaultUser string, systemStyle bool) []protocol.CronEntry {
	var entries []protocol.CronEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip environment variable assignments (e.g., SHELL=/bin/bash).
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "*") &&
			!strings.HasPrefix(line, "@") && (len(line) < 2 || line[0] < '0' || line[0] > '9') {
			continue
		}

		// Handle @reboot, @hourly, etc. shortcuts.
		if strings.HasPrefix(line, "@") {
			fields := strings.Fields(line)
			minFields := 2
			if systemStyle {
				minFields = 3
			}
			if len(fields) < minFields {
				continue
			}
			schedule := fields[0]
			user := defaultUser
			cmdStart := 1
			if systemStyle {
				user = fields[1]
				cmdStart = 2
			}
			rest := strings.Join(fields[cmdStart:], " ")
			entries = append(entries, protocol.CronEntry{
				Source:   "crontab",
				Schedule: schedule,
				Command:  rest,
				User:     user,
			})
			continue
		}

		// Standard 5-field cron schedule.
		fields := strings.Fields(line)
		minFields := 6 // 5 schedule + 1 command
		if systemStyle {
			minFields = 7 // 5 schedule + 1 user + 1 command
		}
		if len(fields) < minFields {
			continue
		}

		schedule := strings.Join(fields[:5], " ")
		user := defaultUser
		cmdStart := 5
		if systemStyle {
			user = fields[5]
			cmdStart = 6
		}
		command := strings.Join(fields[cmdStart:], " ")

		entries = append(entries, protocol.CronEntry{
			Source:   "crontab",
			Schedule: schedule,
			Command:  command,
			User:     user,
		})
	}
	return entries
}

func combineScheduleErrors(errs ...error) error {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		message := strings.TrimSpace(err.Error())
		if message != "" {
			messages = append(messages, message)
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return errors.New(strings.Join(messages, "; "))
}
