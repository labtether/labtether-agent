package webservice

import (
	"github.com/labtether/protocol"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAlternateSchemeURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"http to https", "http://10.0.0.10:8080", "https://10.0.0.10:8080"},
		{"https to http", "https://10.0.0.10:8443", "http://10.0.0.10:8443"},
		{"unsupported scheme", "tcp://10.0.0.10:22", ""},
		{"invalid url", "://bad", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := alternateSchemeURL(tt.in)
			if got != tt.want {
				t.Fatalf("alternateSchemeURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestProbeHealthURLSkipsAlternateWhenPrimaryResponds(t *testing.T) {
	var (
		mu      sync.Mutex
		schemes []string
	)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			schemes = append(schemes, req.URL.Scheme)
			mu.Unlock()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}
	wsc := &WebServiceCollector{client: client}

	result := wsc.probeHealthURL("https://example.local:8443", "/healthz")
	if !result.responded {
		t.Fatal("expected primary probe to respond")
	}
	if result.baseURL != "https://example.local:8443" {
		t.Fatalf("baseURL = %q, want primary URL", result.baseURL)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(schemes) != 1 {
		t.Fatalf("expected one probe request, got %d (%v)", len(schemes), schemes)
	}
	if schemes[0] != "https" {
		t.Fatalf("expected https primary probe, got %q", schemes[0])
	}
}

func TestDoHealthRequestPrefersInsecureClientForHTTPS(t *testing.T) {
	var secureCalls int
	var insecureCalls int

	wsc := &WebServiceCollector{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				secureCalls++
				return nil, io.ErrUnexpectedEOF
			}),
		},
		insecureClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				insecureCalls++
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
					Request:    req,
				}, nil
			}),
		},
	}

	status, ok := wsc.doHealthRequest(http.MethodGet, "https://example.local:8443/healthz")
	if !ok {
		t.Fatal("expected successful health request")
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if insecureCalls != 1 {
		t.Fatalf("insecure calls = %d, want 1", insecureCalls)
	}
	if secureCalls != 0 {
		t.Fatalf("secure calls = %d, want 0", secureCalls)
	}
}

func TestDoBodyRequestPrefersInsecureClientForHTTPS(t *testing.T) {
	var secureCalls int
	var insecureCalls int

	wsc := &WebServiceCollector{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				secureCalls++
				return nil, io.ErrUnexpectedEOF
			}),
		},
		insecureClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				insecureCalls++
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
					Request:    req,
				}, nil
			}),
		},
	}

	body, status, ok := wsc.doBodyRequest(http.MethodGet, "https://example.local:8443/api/health")
	if !ok {
		t.Fatal("expected successful body request")
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if strings.TrimSpace(string(body)) != `{"ok":true}` {
		t.Fatalf("body = %q, want %q", string(body), `{"ok":true}`)
	}
	if insecureCalls != 1 {
		t.Fatalf("insecure calls = %d, want 1", insecureCalls)
	}
	if secureCalls != 0 {
		t.Fatalf("secure calls = %d, want 0", secureCalls)
	}
}

func TestFingerprintKnownServiceSkipsAlternateWhenPrimaryResponds(t *testing.T) {
	var (
		mu      sync.Mutex
		schemes []string
	)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			schemes = append(schemes, req.URL.Scheme)
			mu.Unlock()
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    req,
			}, nil
		}),
	}
	wsc := &WebServiceCollector{client: client}

	if _, ok := wsc.fingerprintKnownService("https://example.local:8443"); ok {
		t.Fatal("expected unknown service fingerprint")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, scheme := range schemes {
		if scheme != "https" {
			t.Fatalf("unexpected alternate probe scheme %q (all requests: %v)", scheme, schemes)
		}
	}
}

func TestFingerprintKnownServiceFallsBackToAlternateWhenPrimaryUnreachable(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Scheme == "https" {
				return nil, io.ErrUnexpectedEOF
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`<html><body>Proxmox Virtual Environment</body></html>`)),
				Request:    req,
			}, nil
		}),
	}
	wsc := &WebServiceCollector{client: client}

	known, ok := wsc.fingerprintKnownService("https://example.local:8443")
	if !ok {
		t.Fatal("expected alternate-scheme fallback to classify service")
	}
	if known.Key != "proxmox" {
		t.Fatalf("known key = %q, want proxmox", known.Key)
	}
}

func TestHealthCheckSwitchesToHTTPS(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsServer.Close()

	parsed, err := neturl.Parse(tlsServer.URL)
	if err != nil {
		t.Fatalf("parse tls server url: %v", err)
	}

	svc := protocol.DiscoveredWebService{
		URL: "http://" + parsed.Host,
	}
	wsc := &WebServiceCollector{
		client: &http.Client{
			Timeout:   2 * time.Second,
			Transport: tlsServer.Client().Transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	wsc.healthCheck(&svc)

	if svc.Status != "up" {
		t.Fatalf("status = %q, want up", svc.Status)
	}
	if !strings.HasPrefix(svc.URL, "https://") {
		t.Fatalf("url = %q, want https://...", svc.URL)
	}
}

func TestHealthCheckSwitchesToHTTP(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	parsed, err := neturl.Parse(httpServer.URL)
	if err != nil {
		t.Fatalf("parse http server url: %v", err)
	}

	svc := protocol.DiscoveredWebService{
		URL: "https://" + parsed.Host,
	}
	wsc := &WebServiceCollector{
		client: &http.Client{
			Timeout: 2 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	wsc.healthCheck(&svc)

	if svc.Status != "up" {
		t.Fatalf("status = %q, want up", svc.Status)
	}
	if !strings.HasPrefix(svc.URL, "http://") {
		t.Fatalf("url = %q, want http://...", svc.URL)
	}
}

func TestApplyHealthCheckWithCacheReusesRecentProbe(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		interval:       time.Minute,
		client:         server.Client(),
		insecureClient: server.Client(),
		healthCache:    make(map[string]healthCacheEntry),
	}
	svc := protocol.DiscoveredWebService{
		ID:  "svc-1",
		URL: server.URL,
	}

	now := time.Now().UTC()
	wsc.applyHealthCheckWithCache(&svc, now)
	if svc.Status != "up" {
		t.Fatalf("first status = %q, want up", svc.Status)
	}

	wsc.applyHealthCheckWithCache(&svc, now.Add(30*time.Second))
	if svc.Status != "up" {
		t.Fatalf("second status = %q, want up", svc.Status)
	}

	mu.Lock()
	got := requests
	mu.Unlock()
	if got != 1 {
		t.Fatalf("probe requests = %d, want 1", got)
	}
}

func TestApplyHealthCheckWithCacheReprobesAfterTTL(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		interval:       time.Minute,
		client:         server.Client(),
		insecureClient: server.Client(),
		healthCache:    make(map[string]healthCacheEntry),
	}
	svc := protocol.DiscoveredWebService{
		ID:  "svc-ttl",
		URL: server.URL,
	}

	now := time.Now().UTC()
	wsc.applyHealthCheckWithCache(&svc, now)
	wsc.applyHealthCheckWithCache(&svc, now.Add(4*time.Minute))

	mu.Lock()
	got := requests
	mu.Unlock()
	if got != 2 {
		t.Fatalf("probe requests = %d, want 2", got)
	}
}
