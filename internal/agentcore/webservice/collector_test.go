package webservice

import (
	"context"
	"crypto/tls"
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type mockCollectorTransport struct {
	mu        sync.Mutex
	connected bool
	sends     int
}

func (m *mockCollectorTransport) Send(protocol.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sends++
	return nil
}

func (m *mockCollectorTransport) Connect(context.Context) error { return nil }

func (m *mockCollectorTransport) Receive() (protocol.Message, error) {
	return protocol.Message{}, nil
}

func (m *mockCollectorTransport) Connected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

func (m *mockCollectorTransport) Close() {}

func TestNewWebServiceCollectorEnforcesTLS12Minimum(t *testing.T) {
	collector := NewWebServiceCollector(nil, "asset", "127.0.0.1", time.Second, nil, WebServiceDiscoveryConfig{})

	for name, client := range map[string]*http.Client{
		"verified": collector.client,
		"insecure": collector.insecureClient,
	} {
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil {
			t.Fatalf("%s client does not have an explicit TLS configuration", name)
		}
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			t.Fatalf("%s client minimum TLS version = %x, want TLS 1.2 or newer", name, transport.TLSClientConfig.MinVersion)
		}
	}
	if !collector.insecureClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure discovery client unexpectedly verifies certificates")
	}
}

func TestMakeServiceID(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		id1 := makeServiceID("192.168.1.10", "docker", "abc123")
		id2 := makeServiceID("192.168.1.10", "docker", "abc123")
		if id1 != id2 {
			t.Errorf("expected deterministic IDs, got %q vs %q", id1, id2)
		}
	})

	t.Run("16 hex chars", func(t *testing.T) {
		id := makeServiceID("host", "source", "id")
		if len(id) != 16 {
			t.Errorf("expected 16-char hex ID, got %d chars: %q", len(id), id)
		}
	})

	t.Run("different inputs produce different IDs", func(t *testing.T) {
		id1 := makeServiceID("192.168.1.10", "docker", "container-a")
		id2 := makeServiceID("192.168.1.10", "docker", "container-b")
		id3 := makeServiceID("192.168.1.20", "docker", "container-a")
		id4 := makeServiceID("192.168.1.10", "systemd", "container-a")

		seen := map[string]bool{id1: true}
		for _, id := range []string{id2, id3, id4} {
			if seen[id] {
				t.Errorf("collision detected: %q appeared more than once", id)
			}
			seen[id] = true
		}
	})
}

func TestBuildServiceURL(t *testing.T) {
	tests := []struct {
		name   string
		hostIP string
		port   int
		want   string
	}{
		{"http standard", "192.168.1.10", 8080, "http://192.168.1.10:8080"},
		{"https 443", "192.168.1.10", 443, "https://192.168.1.10:443"},
		{"https 8443", "10.0.0.1", 8443, "https://10.0.0.1:8443"},
		{"https 9443", "10.0.0.1", 9443, "https://10.0.0.1:9443"},
		{"https 10443", "10.0.0.1", 10443, "https://10.0.0.1:10443"},
		{"https 8006", "10.0.0.1", 8006, "https://10.0.0.1:8006"},
		{"https 8007", "10.0.0.1", 8007, "https://10.0.0.1:8007"},
		{"empty hostIP defaults to localhost", "", 3000, "http://localhost:3000"},
		{"plex port", "192.168.1.5", 32400, "http://192.168.1.5:32400"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildServiceURL(tt.hostIP, tt.port)
			if got != tt.want {
				t.Errorf("buildServiceURL(%q, %d) = %q, want %q", tt.hostIP, tt.port, got, tt.want)
			}
		})
	}
}

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		name  string
		ports []dockerpkg.DockerPort
		want  int
	}{
		{
			"public port mapped",
			[]dockerpkg.DockerPort{{IP: "0.0.0.0", PrivatePort: 32400, PublicPort: 32400, Type: "tcp"}},
			32400,
		},
		{
			"multiple ports returns first public",
			[]dockerpkg.DockerPort{
				{IP: "", PrivatePort: 8080, PublicPort: 0, Type: "tcp"},
				{IP: "0.0.0.0", PrivatePort: 443, PublicPort: 8443, Type: "tcp"},
			},
			8443,
		},
		{
			"no public port",
			[]dockerpkg.DockerPort{{IP: "", PrivatePort: 8080, PublicPort: 0, Type: "tcp"}},
			0,
		},
		{
			"empty ports",
			nil,
			0,
		},
		{
			"different host and container port",
			[]dockerpkg.DockerPort{{IP: "0.0.0.0", PrivatePort: 80, PublicPort: 9090, Type: "tcp"}},
			9090,
		},
		{
			"udp port ignored",
			[]dockerpkg.DockerPort{{IP: "0.0.0.0", PrivatePort: 53, PublicPort: 53, Type: "udp"}},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHostPort(tt.ports)
			if got != tt.want {
				t.Errorf("extractHostPort(%v) = %d, want %d", tt.ports, got, tt.want)
			}
		})
	}
}

func TestExtractHostPortForService(t *testing.T) {
	t.Run("known non-web default prefers web port", func(t *testing.T) {
		ports := []dockerpkg.DockerPort{
			{IP: "0.0.0.0", PrivatePort: 53, PublicPort: 53, Type: "tcp"},
			{IP: "0.0.0.0", PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
		}
		known := &KnownService{DefaultPort: 53}
		got := extractHostPortForService(ports, known)
		if got != 8080 {
			t.Fatalf("extractHostPortForService() = %d, want %d", got, 8080)
		}
	})

	t.Run("known web default uses mapped port", func(t *testing.T) {
		ports := []dockerpkg.DockerPort{
			{IP: "0.0.0.0", PrivatePort: 8080, PublicPort: 18080, Type: "tcp"},
			{IP: "0.0.0.0", PrivatePort: 9000, PublicPort: 9000, Type: "tcp"},
		}
		known := &KnownService{DefaultPort: 8080}
		got := extractHostPortForService(ports, known)
		if got != 18080 {
			t.Fatalf("extractHostPortForService() = %d, want %d", got, 18080)
		}
	})

	t.Run("unknown service prefers likely web port", func(t *testing.T) {
		ports := []dockerpkg.DockerPort{
			{IP: "0.0.0.0", PrivatePort: 53, PublicPort: 53, Type: "tcp"},
			{IP: "0.0.0.0", PrivatePort: 3000, PublicPort: 3000, Type: "tcp"},
		}
		got := extractHostPortForService(ports, nil)
		if got != 3000 {
			t.Fatalf("extractHostPortForService() = %d, want %d", got, 3000)
		}
	})
}

func TestCountDiscoveredServicesBySource(t *testing.T) {
	services := []protocol.DiscoveredWebService{
		{Source: "docker"},
		{Source: "Docker"},
		{Source: "proxy"},
		{Source: "scan"},
		{Source: "scan"},
		{Source: ""},
	}

	got := countDiscoveredServicesBySource(services)
	want := map[string]int{
		"docker":  2,
		"proxy":   1,
		"scan":    2,
		"unknown": 1,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("countDiscoveredServicesBySource() = %#v, want %#v", got, want)
	}
}

func TestRunCycleSkipsWhenTransportDisconnected(t *testing.T) {
	transport := &mockCollectorTransport{connected: false}
	wsc := &WebServiceCollector{
		transport:    transport,
		assetID:      "asset-1",
		interval:     time.Minute,
		discoveryCfg: WebServiceDiscoveryConfig{},
	}

	wsc.RunCycle(context.Background())
	if transport.sends != 0 {
		t.Fatalf("disconnected sends = %d, want 0", transport.sends)
	}

	transport.connected = true
	wsc.RunCycle(context.Background())
	if transport.sends != 1 {
		t.Fatalf("connected sends = %d, want 1", transport.sends)
	}
}
