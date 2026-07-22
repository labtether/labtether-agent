package webservice

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/labtether/protocol"
)

type dynamicWebServiceCaptureTransport struct {
	mu      sync.Mutex
	message protocol.Message
}

func (*dynamicWebServiceCaptureTransport) Connect(context.Context) error { return nil }
func (*dynamicWebServiceCaptureTransport) Receive() (protocol.Message, error) {
	return protocol.Message{}, context.Canceled
}
func (*dynamicWebServiceCaptureTransport) Close()          {}
func (*dynamicWebServiceCaptureTransport) Connected() bool { return true }
func (t *dynamicWebServiceCaptureTransport) Send(msg protocol.Message) error {
	t.mu.Lock()
	t.message = msg
	t.mu.Unlock()
	return nil
}

func (t *dynamicWebServiceCaptureTransport) snapshot() protocol.Message {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.message
}

func TestWebServiceReportBindsCurrentAssetIDAtSendTime(t *testing.T) {
	transport := &dynamicWebServiceCaptureTransport{}
	collector := NewWebServiceCollector(transport, "startup-asset", "127.0.0.1", 0, nil, WebServiceDiscoveryConfig{})
	var currentAssetID atomic.Value
	currentAssetID.Store("canonical-asset")
	collector.SetAssetIDProvider(func() string { return currentAssetID.Load().(string) })

	report := protocol.WebServiceReportData{
		HostAssetID: "startup-asset",
		Services: []protocol.DiscoveredWebService{{
			ID:          "service-1",
			HostAssetID: "startup-asset",
			Source:      "docker",
			URL:         "http://127.0.0.1:8080",
		}},
	}
	currentAssetID.Store("rotated-asset")
	if err := collector.sendReport(report); err != nil {
		t.Fatal(err)
	}

	message := transport.snapshot()
	if message.Type != protocol.MsgWebServiceReport {
		t.Fatalf("message type=%q", message.Type)
	}
	var payload protocol.WebServiceReportData
	if err := json.Unmarshal(message.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.HostAssetID != "rotated-asset" || len(payload.Services) != 1 || payload.Services[0].HostAssetID != "rotated-asset" {
		t.Fatalf("report identities host=%q services=%+v", payload.HostAssetID, payload.Services)
	}
}
