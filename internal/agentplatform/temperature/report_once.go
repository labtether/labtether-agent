package temperature

import (
	"fmt"
	"sync"
)

// ReportOnce passes on the first failed temperature reading and holds back
// the same kind of failure after that, until a reading works again. A host
// without sensors (a VM, a container, most Windows machines) stays that way,
// and the agent's collect loop logged the same warning every five minutes.
type ReportOnce struct {
	mu       sync.Mutex
	reported bool
}

// Filter returns err the first time (worded so the log says it is not
// repeated), nil for later failures, and resets when err is nil.
func (r *ReportOnce) Filter(err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.reported = false
		return nil
	}
	if r.reported {
		return nil
	}
	r.reported = true
	return fmt.Errorf("no temperature reading on this machine (logged once): %w", err)
}
