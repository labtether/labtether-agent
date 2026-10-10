package agentcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/assets"
)

type changingDiskMetadataProvider struct {
	available      string
	staticCalls    int
	heartbeatCalls int
}

func (p *changingDiskMetadataProvider) Collect(now time.Time) (TelemetrySample, error) {
	return TelemetrySample{CollectedAt: now}, nil
}

func (p *changingDiskMetadataProvider) StaticMetadata() map[string]string {
	p.staticCalls++
	return map[string]string{"disk_root_available_bytes": "10", "hostname": "fixed-host"}
}

func (p *changingDiskMetadataProvider) HeartbeatMetadata() map[string]string {
	p.heartbeatCalls++
	return map[string]string{"disk_root_available_bytes": p.available}
}

func (*changingDiskMetadataProvider) AgentInfo() AgentInfo { return AgentInfo{} }

func TestHeartbeatRefreshesAvailableDiskWithoutStaticRescan(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	observed := make(chan assets.HeartbeatRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var heartbeat assets.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&heartbeat); err == nil {
			observed <- heartbeat
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	provider := &changingDiskMetadataProvider{available: "20"}
	cfg := RuntimeConfig{APIBaseURL: server.URL, APIToken: "test-token", AssetID: "node-1", Source: "agent"}
	publisher := NewHeartbeatPublisher(cfg, provider.StaticMetadata())
	runtime := NewRuntime(cfg, provider, publisher)

	runtime.publishOnce(context.Background())
	provider.available = "90"
	runtime.publishOnce(context.Background())

	for _, want := range []string{"20", "90"} {
		select {
		case heartbeat := <-observed:
			if got := heartbeat.Metadata["disk_root_available_bytes"]; got != want {
				t.Fatalf("available bytes=%q, want %q", got, want)
			}
			if heartbeat.Metadata["hostname"] != "fixed-host" {
				t.Fatal("static hostname missing from heartbeat")
			}
		default:
			t.Fatal("heartbeat was not sent")
		}
	}
	if provider.staticCalls != 1 || provider.heartbeatCalls != 2 {
		t.Fatalf("static calls=%d, heartbeat metadata calls=%d; want 1 and 2", provider.staticCalls, provider.heartbeatCalls)
	}
}
