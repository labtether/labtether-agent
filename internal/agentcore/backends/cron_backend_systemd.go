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

	timers, timerErr := CollectSystemdTimers()
	if timerErr != nil {
		return nil, fmt.Errorf("systemd timers: %w", timerErr)
	}
	entries = append(entries, timers...)

	crontabs, crontabErr := CollectCrontabs()
	if crontabErr != nil {
		if len(entries) == 0 {
			return nil, fmt.Errorf("crontabs: %w", crontabErr)
		}
		return entries, nil
	}
	entries = append(entries, crontabs...)

	return entries, nil
}
