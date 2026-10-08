package webservice

import (
	"context"
	"encoding/json"
	"errors"
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProxyProvider struct {
	name     string
	apiURL   string
	detected bool
	routes   []ProxyRoute
	err      error
}

func (f fakeProxyProvider) Name() string {
	if strings.TrimSpace(f.name) == "" {
		return "fake-proxy"
	}
	return f.name
}

func (f fakeProxyProvider) DetectAndConnect([]dockerpkg.DockerContainer) (string, bool) {
	if !f.detected {
		return "", false
	}
	if strings.TrimSpace(f.apiURL) == "" {
		return "http://proxy-admin.local", true
	}
	return f.apiURL, true
}

func (f fakeProxyProvider) FetchRoutes(string) ([]ProxyRoute, error) {
	return f.routes, f.err
}

type recordingCollectorTransport struct {
	mu        sync.Mutex
	connected bool
	messages  []protocol.Message
	ch        chan protocol.Message
	onSend    func(protocol.Message)
}

func newRecordingCollectorTransport(connected bool) *recordingCollectorTransport {
	return &recordingCollectorTransport{
		connected: connected,
		ch:        make(chan protocol.Message, 32),
	}
}

func (r *recordingCollectorTransport) Send(msg protocol.Message) error {
	r.mu.Lock()
	r.messages = append(r.messages, msg)
	r.mu.Unlock()

	select {
	case r.ch <- msg:
	default:
	}
	if r.onSend != nil {
		r.onSend(msg)
	}
	return nil
}

func (r *recordingCollectorTransport) Connect(context.Context) error { return nil }

func (r *recordingCollectorTransport) Receive() (protocol.Message, error) {
	return protocol.Message{}, nil
}

func (r *recordingCollectorTransport) Close() {}

func (r *recordingCollectorTransport) Connected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected
}

func (r *recordingCollectorTransport) MessageCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.messages)
}

func waitForCollectorMessage(t *testing.T, transport *recordingCollectorTransport, timeout time.Duration) protocol.Message {
	t.Helper()

	select {
	case msg := <-transport.ch:
		return msg
	case <-time.After(timeout):
		t.Fatal("timed out waiting for collector transport message")
		return protocol.Message{}
	}
}

func newRootDockerTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	return httptest.NewTLSServer(handler)
}

func TestWebServiceCollectorRunPublishesImmediatelyAndResolvesHostIP(t *testing.T) {
	transport := newRecordingCollectorTransport(true)
	ctx, cancel := context.WithCancel(context.Background())
	transport.onSend = func(protocol.Message) { cancel() }

	wsc := &WebServiceCollector{
		transport:    transport,
		assetID:      "asset-1",
		interval:     10 * time.Millisecond,
		discoveryCfg: WebServiceDiscoveryConfig{},
		nowFn: func() time.Time {
			return time.Date(2026, time.March, 8, 10, 0, 0, 0, time.UTC)
		},
	}

	wsc.Run(ctx)

	if transport.MessageCount() == 0 {
		t.Fatal("expected web-service collector to publish an initial report immediately")
	}
	if strings.TrimSpace(wsc.hostIP) == "" {
		t.Fatal("expected web-service collector to resolve a host IP when starting with an empty hostIP")
	}

	msg := waitForCollectorMessage(t, transport, time.Second)
	if msg.Type != protocol.MsgWebServiceReport {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgWebServiceReport)
	}
}

func TestWebServiceCollectorRunCyclePreservesPreviousDockerServicesOnTransientFailure(t *testing.T) {
	transport := newRecordingCollectorTransport(true)

	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthServer.Close()

	dockerServer := newRootDockerTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			http.Error(w, "docker temporarily unavailable", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer dockerServer.Close()

	dockerCollector := dockerpkg.NewTestCollector(dockerServer.URL, nil, "asset-1")
	dockerCollector.SetTestHTTPClient(dockerServer.Client())

	wsc := &WebServiceCollector{
		transport:        transport,
		assetID:          "asset-1",
		hostIP:           "127.0.0.1",
		docker:           dockerCollector,
		client:           healthServer.Client(),
		insecureClient:   healthServer.Client(),
		discoveryCfg:     WebServiceDiscoveryConfig{DockerEnabled: true},
		lastServices:     []protocol.DiscoveredWebService{{ID: "svc-1", HostAssetID: "asset-1", Source: "docker", URL: healthServer.URL, Name: "Grafana", ServiceKey: "grafana", Category: "Monitoring"}},
		compatCache:      make(map[string]compatCacheEntry),
		fingerprintCache: make(map[string]fingerprintCacheEntry),
		healthCache:      make(map[string]healthCacheEntry),
		nowFn: func() time.Time {
			return time.Date(2026, time.March, 8, 11, 0, 0, 0, time.UTC)
		},
	}

	wsc.RunCycle(context.Background())

	if transport.MessageCount() != 1 {
		t.Fatalf("expected one web-service report, got %d", transport.MessageCount())
	}
	msg := waitForCollectorMessage(t, transport, time.Second)
	if msg.Type != protocol.MsgWebServiceReport {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgWebServiceReport)
	}

	var payload protocol.WebServiceReportData
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode web-service report payload: %v", err)
	}
	if len(payload.Services) != 1 || payload.Services[0].ID != "svc-1" {
		t.Fatalf("expected previous docker service to be preserved, got %+v", payload.Services)
	}
	if payload.Discovery == nil {
		t.Fatal("expected discovery stats to be included in runtime report")
	}
	if payload.Discovery.Sources["docker"].ServicesFound != 0 {
		t.Fatalf("docker services found=%d, want 0 on transient failure", payload.Discovery.Sources["docker"].ServicesFound)
	}
	if payload.Discovery.FinalSourceCount["docker"] != 1 {
		t.Fatalf("final docker service count=%d, want 1 preserved service", payload.Discovery.FinalSourceCount["docker"])
	}
	if len(wsc.lastServices) != 1 || wsc.lastServices[0].ID != "svc-1" {
		t.Fatalf("expected collector cache to retain preserved service, got %+v", wsc.lastServices)
	}
}

func TestWebServiceCollectorRunCyclePublishesProxyOnlyServices(t *testing.T) {
	transport := newRecordingCollectorTransport(true)

	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthServer.Close()

	wsc := &WebServiceCollector{
		transport:      transport,
		assetID:        "asset-1",
		hostIP:         "127.0.0.1",
		client:         healthServer.Client(),
		insecureClient: healthServer.Client(),
		discoveryCfg:   WebServiceDiscoveryConfig{ProxyEnabled: true},
		proxyProviders: []ProxyProvider{
			fakeProxyProvider{
				name:     "traefik",
				apiURL:   "http://proxy-admin.local",
				detected: true,
				routes: []ProxyRoute{
					{
						Domain:     "grafana.home.lab",
						BackendURL: healthServer.URL,
						TLS:        true,
						RouterName: "grafana",
					},
				},
			},
		},
		nowFn: func() time.Time {
			return time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
		},
	}

	wsc.RunCycle(context.Background())

	if transport.MessageCount() != 1 {
		t.Fatalf("expected one web-service report, got %d", transport.MessageCount())
	}
	msg := waitForCollectorMessage(t, transport, time.Second)
	if msg.Type != protocol.MsgWebServiceReport {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgWebServiceReport)
	}

	var payload protocol.WebServiceReportData
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode web-service report payload: %v", err)
	}
	if len(payload.Services) != 1 {
		t.Fatalf("expected one proxy-only service, got %+v", payload.Services)
	}
	service := payload.Services[0]
	if service.Source != "proxy" {
		t.Fatalf("service source=%q, want proxy", service.Source)
	}
	if service.ServiceKey != "grafana" {
		t.Fatalf("service key=%q, want grafana", service.ServiceKey)
	}
	if service.Status != "up" {
		t.Fatalf("service status=%q, want up", service.Status)
	}
	if service.URL != "https://grafana.home.lab" {
		t.Fatalf("service URL=%q, want proxied URL", service.URL)
	}
	if service.Metadata["raw_url"] != healthServer.URL {
		t.Fatalf("raw_url=%q, want %q", service.Metadata["raw_url"], healthServer.URL)
	}
	if payload.Discovery == nil {
		t.Fatal("expected discovery stats to be included in runtime report")
	}
	if payload.Discovery.Sources["proxy"].ServicesFound != 1 {
		t.Fatalf("proxy services found=%d, want 1", payload.Discovery.Sources["proxy"].ServicesFound)
	}
	if payload.Discovery.FinalSourceCount["proxy"] != 1 {
		t.Fatalf("final proxy service count=%d, want 1", payload.Discovery.FinalSourceCount["proxy"])
	}
	if len(wsc.lastServices) != 1 || wsc.lastServices[0].Source != "proxy" {
		t.Fatalf("expected collector cache to retain proxy-only service, got %+v", wsc.lastServices)
	}
}

func TestWebServiceCollectorRunCyclePreservesPreviousProxyServicesOnTransientFailure(t *testing.T) {
	transport := newRecordingCollectorTransport(true)

	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthServer.Close()

	wsc := &WebServiceCollector{
		transport:      transport,
		assetID:        "asset-1",
		hostIP:         "127.0.0.1",
		client:         healthServer.Client(),
		insecureClient: healthServer.Client(),
		discoveryCfg:   WebServiceDiscoveryConfig{ProxyEnabled: true},
		proxyProviders: []ProxyProvider{
			fakeProxyProvider{
				name:     "traefik",
				apiURL:   "http://proxy-admin.local",
				detected: true,
				err:      errors.New("proxy api unavailable"),
			},
		},
		lastServices: []protocol.DiscoveredWebService{
			{
				ID:          "svc-proxy",
				HostAssetID: "asset-1",
				Source:      "proxy",
				URL:         "https://grafana.home.lab",
				Name:        "Grafana",
				ServiceKey:  "grafana",
				Category:    CatMonitoring,
				Metadata: map[string]string{
					"proxy_provider": "traefik",
					"raw_url":        healthServer.URL,
				},
			},
		},
		nowFn: func() time.Time {
			return time.Date(2026, time.March, 8, 12, 30, 0, 0, time.UTC)
		},
	}

	wsc.RunCycle(context.Background())

	if transport.MessageCount() != 1 {
		t.Fatalf("expected one web-service report, got %d", transport.MessageCount())
	}
	msg := waitForCollectorMessage(t, transport, time.Second)
	if msg.Type != protocol.MsgWebServiceReport {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgWebServiceReport)
	}

	var payload protocol.WebServiceReportData
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode web-service report payload: %v", err)
	}
	if len(payload.Services) != 1 || payload.Services[0].ID != "svc-proxy" {
		t.Fatalf("expected previous proxy service to be preserved, got %+v", payload.Services)
	}
	if payload.Services[0].Status != "up" {
		t.Fatalf("preserved proxy service status=%q, want up", payload.Services[0].Status)
	}
	if payload.Discovery == nil {
		t.Fatal("expected discovery stats to be included in runtime report")
	}
	if payload.Discovery.Sources["proxy"].ServicesFound != 0 {
		t.Fatalf("proxy services found=%d, want 0 on transient failure", payload.Discovery.Sources["proxy"].ServicesFound)
	}
	if payload.Discovery.FinalSourceCount["proxy"] != 1 {
		t.Fatalf("final proxy service count=%d, want 1 preserved service", payload.Discovery.FinalSourceCount["proxy"])
	}
	if len(wsc.lastServices) != 1 || wsc.lastServices[0].ID != "svc-proxy" {
		t.Fatalf("expected collector cache to retain preserved proxy service, got %+v", wsc.lastServices)
	}
}
