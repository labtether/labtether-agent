package webservice

import (
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplyFingerprintMetadataLabTetherBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"service":"labtether","status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name:     "Port 8443",
		Category: CatOther,
		URL:      server.URL,
		Source:   "scan",
	}

	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "labtether" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "labtether")
	}
	if svc.Name != "LabTether" {
		t.Fatalf("name = %q, want %q", svc.Name, "LabTether")
	}
	if svc.Category != CatManagement {
		t.Fatalf("category = %q, want %q", svc.Category, CatManagement)
	}
	if svc.Metadata["health_path"] != "/healthz" {
		t.Fatalf("health_path = %q, want %q", svc.Metadata["health_path"], "/healthz")
	}
}

func TestApplyFingerprintMetadataLabTetherFrontend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>LabTether Console</title></head><body>LabTether</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name:     "Port 3000",
		Category: CatOther,
		URL:      server.URL,
		Source:   "scan",
	}

	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "labtether" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "labtether")
	}
	if svc.Name != "LabTether" {
		t.Fatalf("name = %q, want %q", svc.Name, "LabTether")
	}
	if svc.Category != CatManagement {
		t.Fatalf("category = %q, want %q", svc.Category, CatManagement)
	}
}

func TestApplyFingerprintMetadataLabTetherFrontendWithProtectedHealthRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		case "/api/auth/login":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>LabTether Console</title></head><body>LabTether</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name:     "Port 3000",
		Category: CatOther,
		URL:      server.URL,
		Source:   "scan",
	}

	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "labtether" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "labtether")
	}
	if svc.Name != "LabTether" {
		t.Fatalf("name = %q, want %q", svc.Name, "LabTether")
	}
	if svc.Category != CatManagement {
		t.Fatalf("category = %q, want %q", svc.Category, CatManagement)
	}
}

func TestApplyFingerprintMetadataDoesNotMisclassifyGrafanaLikeHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"database":"ok","version":"11.0.0"}`))
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Grafana</title></head><body>grafana</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name:     "Port 3000",
		Category: CatOther,
		URL:      server.URL,
		Source:   "scan",
	}

	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "" {
		t.Fatalf("serviceKey = %q, want empty", svc.ServiceKey)
	}
	if svc.Name != "Port 3000" {
		t.Fatalf("name = %q, want %q", svc.Name, "Port 3000")
	}
}

func TestApplyFingerprintMetadataAppliesCompatibilityFromServiceKey(t *testing.T) {
	wsc := &WebServiceCollector{}
	svc := protocol.DiscoveredWebService{
		Name:       "Portainer",
		Category:   CatManagement,
		URL:        "https://10.0.0.5:9443",
		Source:     "docker",
		ServiceKey: "portainer",
	}

	wsc.applyFingerprintMetadata(&svc)

	if svc.Metadata == nil {
		t.Fatal("expected metadata to be initialized")
	}
	if svc.Metadata["compat_connector"] != "portainer" {
		t.Fatalf("compat_connector = %q, want %q", svc.Metadata["compat_connector"], "portainer")
	}
	if svc.Metadata["compat_confidence"] == "" {
		t.Fatal("expected compat_confidence metadata")
	}
	if svc.Metadata["compat_auth_hint"] == "" {
		t.Fatal("expected compat_auth_hint metadata")
	}
}

func TestApplyFingerprintMetadataDetectsHomeAssistantCompatibility(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"message":"API running."}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name:     "Port 8123",
		Category: CatOther,
		URL:      server.URL,
		Source:   "scan",
	}

	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "homeassistant" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "homeassistant")
	}
	if svc.Name != "Home Assistant" {
		t.Fatalf("name = %q, want %q", svc.Name, "Home Assistant")
	}
	if svc.Metadata == nil {
		t.Fatal("expected metadata to be initialized")
	}
	if svc.Metadata["compat_connector"] != "homeassistant" {
		t.Fatalf("compat_connector = %q, want %q", svc.Metadata["compat_connector"], "homeassistant")
	}
	if svc.Metadata["compat_profile"] != "homeassistant.api.root" {
		t.Fatalf("compat_profile = %q, want %q", svc.Metadata["compat_profile"], "homeassistant.api.root")
	}
}

func TestNormalizeLabTetherServicesHidesAPIWhenConsoleExists(t *testing.T) {
	services := []protocol.DiscoveredWebService{
		{
			ID:          "svc-console",
			ServiceKey:  "labtether",
			Name:        "LabTether",
			Category:    CatManagement,
			URL:         "https://10.0.0.5:3000",
			Source:      "scan",
			HostAssetID: "host-a",
			Metadata: map[string]string{
				"public_port": "3000",
			},
		},
		{
			ID:          "svc-api",
			ServiceKey:  "labtether",
			Name:        "LabTether",
			Category:    CatManagement,
			URL:         "https://10.0.0.5:8443",
			Source:      "scan",
			HostAssetID: "host-a",
			Metadata: map[string]string{
				"public_port": "8443",
			},
		},
	}

	normalizeLabTetherServices(services)

	if services[0].Name != "LabTether Console" {
		t.Fatalf("console name = %q, want %q", services[0].Name, "LabTether Console")
	}
	if services[0].Metadata["labtether_component"] != labtetherConsole {
		t.Fatalf("console component = %q, want %q", services[0].Metadata["labtether_component"], labtetherConsole)
	}
	if services[0].Metadata["hidden"] == "true" {
		t.Fatalf("console hidden = %q, want not hidden", services[0].Metadata["hidden"])
	}

	if services[1].Name != "LabTether API" {
		t.Fatalf("api name = %q, want %q", services[1].Name, "LabTether API")
	}
	if services[1].Metadata["labtether_component"] != labtetherAPI {
		t.Fatalf("api component = %q, want %q", services[1].Metadata["labtether_component"], labtetherAPI)
	}
	if services[1].Metadata["hidden"] != "true" {
		t.Fatalf("api hidden = %q, want %q", services[1].Metadata["hidden"], "true")
	}
}

func TestNormalizeLabTetherServicesShowsAPIWithoutConsole(t *testing.T) {
	services := []protocol.DiscoveredWebService{
		{
			ID:          "svc-api",
			ServiceKey:  "labtether",
			Name:        "LabTether",
			Category:    CatManagement,
			URL:         "https://10.0.0.5:8443",
			Source:      "scan",
			HostAssetID: "host-a",
			Metadata: map[string]string{
				"public_port": "8443",
			},
		},
	}

	normalizeLabTetherServices(services)

	if services[0].Name != "LabTether API" {
		t.Fatalf("api name = %q, want %q", services[0].Name, "LabTether API")
	}
	if services[0].Metadata["labtether_component"] != labtetherAPI {
		t.Fatalf("api component = %q, want %q", services[0].Metadata["labtether_component"], labtetherAPI)
	}
	if services[0].Metadata["hidden"] == "true" {
		t.Fatalf("api hidden = %q, want visible", services[0].Metadata["hidden"])
	}
}

func TestFingerprintNoMatchOnGenericService(t *testing.T) {
	// A generic web app should not match any fingerprint.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>My App</title></head><body>Welcome</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name: "Port 9000", Category: CatOther, URL: server.URL, Source: "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "" {
		t.Fatalf("generic service matched serviceKey = %q, want empty", svc.ServiceKey)
	}
}

func TestFingerprintSkipsAlreadyClassified(t *testing.T) {
	// Services that already have a ServiceKey should not be re-fingerprinted.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>TrueNAS</body></html>`))
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client:         server.Client(),
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		ServiceKey: "myapp",
		Name:       "My App",
		Category:   CatOther,
		URL:        server.URL,
		Source:     "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "myapp" {
		t.Fatalf("serviceKey changed to %q, should remain %q", svc.ServiceKey, "myapp")
	}
}
