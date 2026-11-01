package agentcore

import (
	"context"
	"testing"
	"time"
)

// slowFirstCollectProvider holds its collection until released, like the
// first gopsutil/WMI read on Windows or macOS.
type slowFirstCollectProvider struct {
	release chan struct{}
}

func (p *slowFirstCollectProvider) Collect(now time.Time) (TelemetrySample, error) {
	<-p.release
	return TelemetrySample{CPUPercent: 42, MemoryPercent: 61, DiskPercent: 70, CollectedAt: now}, nil
}

func (*slowFirstCollectProvider) StaticMetadata() map[string]string { return map[string]string{} }
func (*slowFirstCollectProvider) AgentInfo() AgentInfo              { return AgentInfo{} }

// The first heartbeat used to go out with the zeroed placeholder whenever the
// first collection was slower than the heartbeat loop's start, and the Hub
// stored those zeros as the host's first readings.
func TestFirstHeartbeatWaitsForRealTelemetry(t *testing.T) {
	provider := &slowFirstCollectProvider{release: make(chan struct{})}
	publisher := &recordingHeartbeatPublisher{}
	runtime := NewRuntime(RuntimeConfig{AssetID: "node-1", CollectInterval: time.Hour, HeartbeatInterval: time.Hour}, provider, publisher)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runtime.collectLoop(ctx)
	go runtime.heartbeatLoop(ctx)
	time.Sleep(50 * time.Millisecond)
	if got := publisher.snapshot(); len(got) != 0 {
		t.Fatalf("heartbeat sent before the first collection: %+v", got)
	}
	close(provider.release)

	deadline := time.After(2 * time.Second)
	for len(publisher.snapshot()) == 0 {
		select {
		case <-deadline:
			t.Fatal("no heartbeat after the first collection")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if first := publisher.snapshot()[0]; first.pending || first.CPUPercent != 42 || first.MemoryPercent != 61 {
		t.Fatalf("first heartbeat = %+v, want the collected values", first)
	}

	if metadata := heartbeatMetadata(nil, TelemetrySample{pending: true}); metadata["cpu_percent"] != "" {
		t.Fatalf("placeholder carried metrics: %v", metadata)
	}
}
