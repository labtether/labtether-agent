package agentcore

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdog_DetectsStuck(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	var counter atomic.Int64
	var exitCode atomic.Int32

	cfg := WatchdogConfig{
		HeartbeatCounter: &counter,
		CheckInterval:    100 * time.Millisecond,
		StuckThreshold:   300 * time.Millisecond,
		ExitFunc:         func(code int) { exitCode.Store(int32(code)) },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go RunWatchdog(ctx, cfg)

	// Don't bump the counter — watchdog should detect stuck.
	time.Sleep(time.Second)

	if exitCode.Load() != 11 {
		t.Fatalf("expected exit code 11, got %d", exitCode.Load())
	}
	if !strings.Contains(buf.String(), "stuck") {
		t.Errorf("expected 'stuck' in log, got: %s", buf.String())
	}
}

func TestWatchdog_HealthyDoesNotExit(t *testing.T) {
	var counter atomic.Int64
	var exitCode atomic.Int32

	cfg := WatchdogConfig{
		HeartbeatCounter: &counter,
		CheckInterval:    50 * time.Millisecond,
		StuckThreshold:   500 * time.Millisecond,
		ExitFunc:         func(code int) { exitCode.Store(int32(code)) },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	// Bump counter periodically.
	go func() {
		for ctx.Err() == nil {
			counter.Add(1)
			time.Sleep(30 * time.Millisecond)
		}
	}()

	RunWatchdog(ctx, cfg)

	if exitCode.Load() != 0 {
		t.Fatalf("expected no exit, got code %d", exitCode.Load())
	}
}
