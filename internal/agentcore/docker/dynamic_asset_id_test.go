package docker

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/labtether/protocol"
)

type dynamicIdentityCaptureTransport struct {
	mu       sync.Mutex
	messages []protocol.Message
}

func (*dynamicIdentityCaptureTransport) Connect(context.Context) error { return nil }
func (*dynamicIdentityCaptureTransport) Receive() (protocol.Message, error) {
	return protocol.Message{}, context.Canceled
}
func (*dynamicIdentityCaptureTransport) Close()          {}
func (*dynamicIdentityCaptureTransport) Connected() bool { return true }
func (t *dynamicIdentityCaptureTransport) Send(msg protocol.Message) error {
	t.mu.Lock()
	t.messages = append(t.messages, msg)
	t.mu.Unlock()
	return nil
}

func (t *dynamicIdentityCaptureTransport) snapshot() []protocol.Message {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]protocol.Message, len(t.messages))
	copy(out, t.messages)
	return out
}

func TestDockerOutboundMessagesBindCurrentAssetIDAtSendTime(t *testing.T) {
	transport := &dynamicIdentityCaptureTransport{}
	collector := NewDockerCollector("/tmp/not-used.sock", transport, "startup-asset", 0)
	var currentAssetID atomic.Value
	currentAssetID.Store("canonical-asset")
	collector.SetAssetIDProvider(func() string { return currentAssetID.Load().(string) })

	if err := collector.sendDockerMessage(protocol.MsgDockerDiscovery, protocol.DockerDiscoveryData{HostID: "startup-asset"}); err != nil {
		t.Fatal(err)
	}
	if err := collector.sendDockerMessage(protocol.MsgDockerDiscoveryDelta, protocol.DockerDiscoveryDeltaData{HostID: "startup-asset"}); err != nil {
		t.Fatal(err)
	}
	currentAssetID.Store("rotated-asset")
	if err := collector.sendDockerMessage(protocol.MsgDockerStats, protocol.DockerStatsData{HostID: "startup-asset"}); err != nil {
		t.Fatal(err)
	}
	collector.forwardEvent(DockerEvent{Type: "container", Action: "start"})

	messages := transport.snapshot()
	if len(messages) != 4 {
		t.Fatalf("messages=%d, want 4", len(messages))
	}
	var discovery protocol.DockerDiscoveryData
	if err := json.Unmarshal(messages[0].Data, &discovery); err != nil {
		t.Fatal(err)
	}
	var delta protocol.DockerDiscoveryDeltaData
	if err := json.Unmarshal(messages[1].Data, &delta); err != nil {
		t.Fatal(err)
	}
	var stats protocol.DockerStatsData
	if err := json.Unmarshal(messages[2].Data, &stats); err != nil {
		t.Fatal(err)
	}
	var event protocol.DockerEventData
	if err := json.Unmarshal(messages[3].Data, &event); err != nil {
		t.Fatal(err)
	}
	if discovery.HostID != "canonical-asset" || delta.HostID != "canonical-asset" {
		t.Fatalf("discovery identities=%q/%q", discovery.HostID, delta.HostID)
	}
	if stats.HostID != "rotated-asset" || event.HostID != "rotated-asset" {
		t.Fatalf("post-rotation identities=%q/%q", stats.HostID, event.HostID)
	}
}
