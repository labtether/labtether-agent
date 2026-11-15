package agentcore

import (
	"context"
	"sync"
	"time"
)

// collectWaitLimit bounds how long a heartbeat waits for a collection that is
// due or running when the heartbeat falls due. The slowest collection step is
// the temperature read (1.5 s for gopsutil plus 2 s for the fallback on
// Windows and macOS), so 5 s covers a slow but working collection. It is also
// the shortest heartbeat interval allowed, so a stuck collection delays one
// heartbeat by at most one interval, far below the watchdog's 5 minutes.
const collectWaitLimit = 5 * time.Second

// collectSchedule lets a heartbeat that falls due together with a collection
// go out with that collection's sample, as the Rust agent does. Without it the
// two loops raced: when the heartbeat loop ran first it sent the previous
// sample again and the new reading was never sent.
//
// The collect loop records when its next collection is due and whether one
// is running. The heartbeat loop compares its own due time with that and, when
// a collection is due or running, waits until it finishes, for at most
// collectWaitLimit. Only the heartbeat loop ever waits, and only on a channel
// the collect loop closes without holding any other lock, so the two cannot
// deadlock, and a slow publish never delays a collection. Both loops time their
// ticks from the same start, so with equal intervals each heartbeat is due at
// exactly the time of a collection.
type collectSchedule struct {
	mu      sync.Mutex
	anchor  time.Time     // start of the first collection; zero before it
	nextDue time.Time     // when the next collection is due; zero when the loop is not running
	running bool          // a collection is in progress
	runs    uint64        // finished collections
	done    chan struct{} // closed and replaced when a collection finishes
}

func (s *collectSchedule) doneLocked() chan struct{} {
	if s.done == nil {
		s.done = make(chan struct{})
	}
	return s.done
}

// begin marks a collection as running. The first call also sets the anchor.
func (s *collectSchedule) begin(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor.IsZero() {
		s.anchor = now
	}
	s.running = true
	s.doneLocked()
}

// finish records a finished collection and when the next one is due, and
// wakes any heartbeat waiting for it.
func (s *collectSchedule) finish(next time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	s.nextDue = next
	s.runs++
	close(s.doneLocked())
	s.done = make(chan struct{})
}

// stop records that the collect loop has ended, so no heartbeat waits for it.
func (s *collectSchedule) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	s.nextDue = time.Time{}
	close(s.doneLocked())
	s.done = make(chan struct{})
}

// heartbeatAnchor returns the start the heartbeat ticks are timed from.
func (s *collectSchedule) heartbeatAnchor(fallback time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor.IsZero() {
		return fallback
	}
	return s.anchor
}

// pending reports whether a heartbeat due at due must wait for a collection,
// with the channel to wait on and the number of finished collections.
func (s *collectSchedule) pending(due time.Time) (<-chan struct{}, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wait := s.running || (!s.nextDue.IsZero() && !s.nextDue.After(due))
	return s.doneLocked(), s.runs, wait
}

// awaitDueCollection holds a heartbeat due at due until a collection that is
// due or running by then has finished, for at most limit. After one timed-out
// wait it does not wait again for the same collection, so a stuck collection
// does not slow every later heartbeat. It returns false when ctx ends.
func (s *collectSchedule) awaitDueCollection(ctx context.Context, due time.Time, limit time.Duration, gaveUpAt *uint64) bool {
	done, runs, wait := s.pending(due)
	if !wait || runs == *gaveUpAt {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		*gaveUpAt = runs
	case <-ctx.Done():
		return false
	}
	return true
}

// nextTick returns the first tick after now on the grid due, due+every, ...
// Ticks already missed are skipped, as a time.Ticker drops them, and the grid
// is kept, so two loops timed from the same start with the same interval stay
// on the same ticks even after a slow collection. A zero interval never comes
// from the configuration; it is treated as one second so it cannot spin a loop.
func nextTick(due time.Time, every time.Duration, now time.Time) time.Time {
	if every <= 0 {
		every = time.Second
	}
	next := due.Add(every)
	if !next.After(now) {
		next = due.Add((now.Sub(due)/every + 1) * every)
	}
	return next
}

// collectInterval is the interval the collect loop uses for its next tick: an
// override from the Hub or the settings, or the configured value, which a
// config.update with 0 restores.
func (r *Runtime) collectInterval() time.Duration {
	if override := r.collectIntervalOverride.Load(); override > 0 {
		return time.Duration(override) * time.Second
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg.CollectInterval
}

// heartbeatInterval is the interval the heartbeat loop uses for its next tick,
// chosen as collectInterval chooses.
func (r *Runtime) heartbeatInterval() time.Duration {
	if override := r.heartbeatIntervalOverride.Load(); override > 0 {
		return time.Duration(override) * time.Second
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg.HeartbeatInterval
}

// heartbeatCollectWait is the bound for awaitDueCollection; tests shorten it.
func (r *Runtime) heartbeatCollectWait() time.Duration {
	if r.collectWaitLimit > 0 {
		return r.collectWaitLimit
	}
	return collectWaitLimit
}
