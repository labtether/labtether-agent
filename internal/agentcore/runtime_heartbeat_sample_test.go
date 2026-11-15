package agentcore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sequenceProvider numbers its samples (CPUPercent = collection number) and
// holds collection number hold until release is closed or holdFor passes.
type sequenceProvider struct {
	calls   atomic.Int64
	hold    int64
	release chan struct{}
	holdFor time.Duration
}

func (p *sequenceProvider) Collect(now time.Time) (TelemetrySample, error) {
	n := p.calls.Add(1)
	if n == p.hold {
		select {
		case <-p.release:
		case <-time.After(p.holdFor):
		}
	}
	return TelemetrySample{CPUPercent: float64(n), CollectedAt: now}, nil
}

func (*sequenceProvider) StaticMetadata() map[string]string { return map[string]string{} }
func (*sequenceProvider) AgentInfo() AgentInfo              { return AgentInfo{} }

// signallingPublisher records heartbeats and closes second when the second
// one is published.
type signallingPublisher struct {
	recordingHeartbeatPublisher
	second chan struct{}
	once   sync.Once
}

func (p *signallingPublisher) Publish(ctx context.Context, sample TelemetrySample) error {
	err := p.recordingHeartbeatPublisher.Publish(ctx, sample)
	if len(p.snapshot()) >= 2 {
		p.once.Do(func() { close(p.second) })
	}
	return err
}

func waitForHeartbeats(t *testing.T, publisher *signallingPublisher, count int, limit time.Duration) []TelemetrySample {
	t.Helper()
	deadline := time.After(limit)
	for {
		if got := publisher.snapshot(); len(got) >= count {
			return got
		}
		select {
		case <-deadline:
			t.Fatalf("%d heartbeats within %s, want %d", len(publisher.snapshot()), limit, count)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Fault: the collect and heartbeat loops raced. With both due together, a
// heartbeat that ran while the collection was still running sent the
// previous sample again, and the new reading was never sent. The second
// collection here is held until the second heartbeat goes out (or 2 s pass),
// so the old code always sends sample 1 twice. The fixed heartbeat waits
// for the collection and carries sample 2.
func TestHeartbeatDueWithCollectionSendsTheNewSample(t *testing.T) {
	publisher := &signallingPublisher{second: make(chan struct{})}
	provider := &sequenceProvider{hold: 2, release: publisher.second, holdFor: 2 * time.Second}
	runtime := NewRuntime(RuntimeConfig{AssetID: "node-1", CollectInterval: 50 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond}, provider, publisher)
	runtime.collectWaitLimit = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runtime.collectLoop(ctx)
	go runtime.heartbeatLoop(ctx)

	got := waitForHeartbeats(t, publisher, 2, 10*time.Second)
	if got[0].CPUPercent != 1 || got[1].CPUPercent != 2 {
		t.Fatalf("heartbeats carried samples %v then %v, want 1 then 2", got[0].CPUPercent, got[1].CPUPercent)
	}
}

// Risk: waiting for a collection must not stop heartbeats. A stuck collection
// would leave the device offline in the Hub and the watchdog would restart
// the agent. After the bounded wait the heartbeat goes out with the previous
// sample, and later heartbeats keep their interval.
func TestStuckCollectionDoesNotStopHeartbeats(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	publisher := &signallingPublisher{second: make(chan struct{})}
	provider := &sequenceProvider{hold: 2, release: stuck, holdFor: time.Hour}
	runtime := NewRuntime(RuntimeConfig{AssetID: "node-1", CollectInterval: 50 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond}, provider, publisher)
	runtime.collectWaitLimit = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runtime.collectLoop(ctx)
	go runtime.heartbeatLoop(ctx)

	got := waitForHeartbeats(t, publisher, 5, 10*time.Second)
	for i, sample := range got {
		if sample.CPUPercent != 1 {
			t.Fatalf("heartbeat %d carried sample %v while collection 2 is stuck, want 1", i, sample.CPUPercent)
		}
	}
	if counter := runtime.HeartbeatCounter.Load(); counter < 4 {
		t.Fatalf("watchdog heartbeat counter=%d, want at least 4", counter)
	}
}
