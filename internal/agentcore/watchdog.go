package agentcore

import (
	"context"
	"log"
	"runtime"
	"sync/atomic"
	"time"
)

const (
	watchdogExitCode          = 11
	defaultWatchdogInterval   = 60 * time.Second
	defaultStuckThreshold     = 5 * time.Minute
	goroutineWarningThreshold = 500
)

// WatchdogConfig configures the watchdog goroutine.
type WatchdogConfig struct {
	HeartbeatCounter *atomic.Int64
	CheckInterval    time.Duration
	StuckThreshold   time.Duration
	ExitFunc         func(code int) // os.Exit in production, mock in tests
}

// RunWatchdog monitors the heartbeat counter and goroutine count.
// If the heartbeat counter hasn't changed for StuckThreshold, it logs
// an error and calls ExitFunc(11). Exits when ctx is cancelled.
func RunWatchdog(ctx context.Context, cfg WatchdogConfig) {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = defaultWatchdogInterval
	}
	if cfg.StuckThreshold == 0 {
		cfg.StuckThreshold = defaultStuckThreshold
	}

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	lastValue := cfg.HeartbeatCounter.Load()
	lastChange := time.Now()
	lastGoroutines := runtime.NumGoroutine()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := cfg.HeartbeatCounter.Load()
			if current != lastValue {
				lastValue = current
				lastChange = time.Now()
			} else if time.Since(lastChange) > cfg.StuckThreshold {
				log.Printf("watchdog: heartbeat stuck for %v (counter=%d), exiting with code %d",
					time.Since(lastChange).Round(time.Second), current, watchdogExitCode)
				buf := make([]byte, 64*1024)
				n := runtime.Stack(buf, true)
				log.Printf("watchdog: goroutine dump:\n%s", buf[:n])
				if cfg.ExitFunc != nil {
					cfg.ExitFunc(watchdogExitCode)
				}
				return
			}

			// Goroutine leak detection.
			numGoroutines := runtime.NumGoroutine()
			if numGoroutines > goroutineWarningThreshold && lastGoroutines > 0 {
				growth := float64(numGoroutines-lastGoroutines) / float64(lastGoroutines)
				if growth > 0.5 {
					log.Printf("watchdog: goroutine count %d (was %d, +%.0f%%) — possible leak",
						numGoroutines, lastGoroutines, growth*100)
				}
			}
			lastGoroutines = numGoroutines
		}
	}
}
