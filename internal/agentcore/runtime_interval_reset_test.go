package agentcore

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type countingProvider struct{ calls atomic.Int64 }

func (p *countingProvider) Collect(now time.Time) (TelemetrySample, error) {
	p.calls.Add(1)
	return TelemetrySample{CPUPercent: 1, CollectedAt: now}, nil
}

func (*countingProvider) StaticMetadata() map[string]string { return map[string]string{} }
func (*countingProvider) AgentInfo() AgentInfo              { return AgentInfo{} }

type discardSender struct{}

func (discardSender) Send(protocol.Message) error { return nil }

func sendIntervals(t *testing.T, runtime *Runtime, collect, heartbeat int) {
	t.Helper()
	data, err := json.Marshal(protocol.ConfigUpdateData{CollectIntervalSec: &collect, HeartbeatIntervalSec: &heartbeat})
	if err != nil {
		t.Fatalf("marshal config update: %v", err)
	}
	handleConfigUpdate(discardSender{}, protocol.Message{Type: protocol.MsgConfigUpdate, Data: data}, runtime)
}

func waitUntil(t *testing.T, limit time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.After(limit)
	for !done() {
		select {
		case <-deadline:
			t.Fatalf("not within %s: %s", limit, what)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Fault: config.update with 0 changed the reply and the saved file, but both
// loops only acted on an override above 0, so the running intervals stayed at
// the last override until the agent restarted, and the watchdog kept scaling
// from it. A reset must reach each running loop by its next tick.
func TestConfigUpdateResetReachesTheRunningLoops(t *testing.T) {
	base := 20 * time.Millisecond
	provider := &countingProvider{}
	runtime := NewRuntime(RuntimeConfig{AssetID: "node-1", CollectInterval: base, HeartbeatInterval: base,
		AllowRemoteOverrides: true, TokenFilePath: filepath.Join(t.TempDir(), "agent-token")},
		provider, noopHeartbeatPublisher{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runtime.collectLoop(ctx)
	go runtime.heartbeatLoop(ctx)

	sendIntervals(t, runtime, 2, 5)
	waitUntil(t, 10*time.Second, "heartbeat interval 5s", func() bool {
		return runtime.watchdogHeartbeatInterval() == 5*time.Second
	})
	// The first collection after the update applies 2 s; the next comes 2 s later.
	start := provider.calls.Load()
	waitUntil(t, 10*time.Second, "two collections after the update", func() bool {
		return provider.calls.Load() >= start+2
	})

	sendIntervals(t, runtime, 0, 0)
	afterReset := provider.calls.Load()
	// The heartbeat loop ticks once more on 5 s, then must be back on 20 ms.
	waitUntil(t, 15*time.Second, "heartbeat interval back to the start value", func() bool {
		return runtime.watchdogHeartbeatInterval() == base
	})
	// On 2 s, 10 s gives at most 5 collections; back on 20 ms it gives hundreds.
	waitUntil(t, 10*time.Second, "collect interval back to the start value", func() bool {
		return provider.calls.Load() >= afterReset+10
	})
}
