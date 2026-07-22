package backends

import (
	"fmt"

	"github.com/labtether/protocol"
)

// LinuxCronBackend implements CronBackend using systemd timers and crontabs.
type LinuxCronBackend struct{}

// ListEntries lists systemd timers and crontab entries.
func (LinuxCronBackend) ListEntries() ([]protocol.CronEntry, error) {
	var entries []protocol.CronEntry
	var collectionErrors []error

	timers, timerErr := CollectSystemdTimers()
	if timerErr != nil {
		collectionErrors = append(collectionErrors, fmt.Errorf("systemd timers: %w", timerErr))
	}
	entries = append(entries, timers...)

	crontabs, crontabErr := CollectCrontabs()
	if crontabErr != nil {
		collectionErrors = append(collectionErrors, fmt.Errorf("crontabs: %w", crontabErr))
	}
	entries = append(entries, crontabs...)

	return entries, combineScheduleErrors(collectionErrors...)
}
