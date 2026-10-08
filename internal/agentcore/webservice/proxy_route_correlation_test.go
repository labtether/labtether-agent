package webservice

import (
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
	"testing"
)

func TestEnrichServicesTraefikProxyOnlyBackendDedup(t *testing.T) {
	hostAssetID := "asset-traefik-proxy-dedup"
	hostIP := "10.0.1.1"

	routes := []ProxyRoute{
		{
			Domain:     "grafana.home.lab",
			BackendURL: "http://10.0.1.10:3000",
			TLS:        true,
			RouterName: "grafana-primary",
		},
		{
			Domain:     "monitor.home.lab",
			BackendURL: "http://10.0.1.10:3000",
			TLS:        true,
			RouterName: "grafana-alias",
		},
		{
			Domain:     "monitor.home.lab",
			BackendURL: "http://10.0.1.10:3000",
			TLS:        true,
			RouterName: "grafana-alias-duplicate",
		},
	}

	result := enrichServicesWithRoutes(nil, routes, "traefik", hostAssetID, hostIP, nil)
	if len(result) != 1 {
		t.Fatalf("got %d services; want 1 deduplicated proxy-only service", len(result))
	}

	svc := result[0]
	if svc.URL != "https://grafana.home.lab" {
		t.Errorf("URL = %q; want %q", svc.URL, "https://grafana.home.lab")
	}
	if svc.Metadata["backend_url"] != "http://10.0.1.10:3000" {
		t.Errorf("backend_url = %q; want %q", svc.Metadata["backend_url"], "http://10.0.1.10:3000")
	}
	if svc.Metadata["alt_urls"] != "https://monitor.home.lab" {
		t.Errorf("alt_urls = %q; want %q", svc.Metadata["alt_urls"], "https://monitor.home.lab")
	}
}

func TestEnrichServicesTraefikSkipsDuplicatePrimaryAlias(t *testing.T) {
	hostAssetID := "asset-traefik-alias-dedup"
	hostIP := "10.0.1.1"

	containers := []dockerpkg.DockerContainer{
		{
			ID:    "app-ctr",
			Names: []string{"/app"},
			Image: "nginx",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
			},
		},
	}

	services := []protocol.DiscoveredWebService{
		{
			ID:          "svc-app",
			Name:        "app",
			URL:         "http://10.0.1.1:8080",
			Source:      "docker",
			ContainerID: "app-ctr",
			HostAssetID: hostAssetID,
		},
	}

	routes := []ProxyRoute{
		{
			Domain:     "app.home.lab",
			BackendURL: "http://172.18.0.10:80",
			TLS:        true,
			RouterName: "app-primary",
		},
		{
			Domain:     "app.home.lab",
			BackendURL: "http://172.18.0.10:80",
			TLS:        true,
			RouterName: "app-duplicate",
		},
		{
			Domain:     "app-alt.home.lab",
			BackendURL: "http://172.18.0.10:80",
			TLS:        true,
			RouterName: "app-alias",
		},
	}

	result := enrichServicesWithRoutes(services, routes, "traefik", hostAssetID, hostIP, containers)
	if len(result) != 1 {
		t.Fatalf("got %d services; want 1", len(result))
	}

	svc := result[0]
	if svc.URL != "https://app.home.lab" {
		t.Errorf("URL = %q; want %q", svc.URL, "https://app.home.lab")
	}
	if svc.Metadata["alt_urls"] != "https://app-alt.home.lab" {
		t.Errorf("alt_urls = %q; want %q", svc.Metadata["alt_urls"], "https://app-alt.home.lab")
	}
}

// ---------------------------------------------------------------------------
// TestEnrichServicesDoubleEnrichGuard
// ---------------------------------------------------------------------------

func TestEnrichServicesDoubleEnrichGuard(t *testing.T) {
	hostAssetID := "asset-guard"
	hostIP := "10.0.1.1"

	containers := []dockerpkg.DockerContainer{
		{
			ID:    "grafana-ctr",
			Names: []string{"/grafana"},
			Image: "grafana/grafana",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{PrivatePort: 3000, PublicPort: 3000, Type: "tcp"},
			},
		},
	}

	// Service already enriched by a previous proxy provider (e.g. Traefik).
	services := []protocol.DiscoveredWebService{
		{
			ID:          "svc-grafana",
			ServiceKey:  "grafana",
			Name:        "Grafana",
			URL:         "https://grafana.home.lab",
			Source:      "docker",
			ContainerID: "grafana-ctr",
			HostAssetID: hostAssetID,
			Metadata: map[string]string{
				"raw_url":        "http://10.0.1.1:3000",
				"proxy_provider": "traefik",
			},
		},
	}

	// Second provider (Caddy) also routes to the same backend.
	routes := []ProxyRoute{
		{
			Domain:     "grafana.caddy.lab",
			BackendURL: "http://10.0.1.1:3000",
			TLS:        true,
			RouterName: "grafana-caddy",
		},
	}

	result := enrichServicesWithRoutes(services, routes, "caddy", hostAssetID, hostIP, containers)

	var grafanaSvc *protocol.DiscoveredWebService
	for i := range result {
		if result[i].ServiceKey == "grafana" {
			grafanaSvc = &result[i]
			break
		}
	}

	if grafanaSvc == nil {
		t.Fatal("grafana service not found")
	}

	// URL should NOT be overwritten by the second provider.
	if grafanaSvc.URL != "https://grafana.home.lab" {
		t.Errorf("grafana URL = %q; want %q (should not be overwritten)", grafanaSvc.URL, "https://grafana.home.lab")
	}

	// proxy_provider should remain "traefik" (first provider).
	if grafanaSvc.Metadata["proxy_provider"] != "traefik" {
		t.Errorf("proxy_provider = %q; want %q", grafanaSvc.Metadata["proxy_provider"], "traefik")
	}

	// raw_url should remain the original.
	if grafanaSvc.Metadata["raw_url"] != "http://10.0.1.1:3000" {
		t.Errorf("raw_url = %q; want %q", grafanaSvc.Metadata["raw_url"], "http://10.0.1.1:3000")
	}

	// The second provider's domain should be in alt_urls.
	altURLs := grafanaSvc.Metadata["alt_urls"]
	if altURLs != "https://grafana.caddy.lab" {
		t.Errorf("alt_urls = %q; want %q", altURLs, "https://grafana.caddy.lab")
	}
}

// ---------------------------------------------------------------------------
// TestEnrichServicesTraefikRouterLabelCorrelation
// ---------------------------------------------------------------------------

func TestEnrichServicesTraefikRouterLabelCorrelation(t *testing.T) {
	hostAssetID := "asset-router-map"
	hostIP := "10.0.1.1"

	// Two containers share private port 80, which is ambiguous by port alone.
	containers := []dockerpkg.DockerContainer{
		{
			ID:    "app1-ctr",
			Names: []string{"/app1"},
			Image: "nginx",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{PrivatePort: 80, PublicPort: 8081, Type: "tcp"},
			},
			Labels: map[string]string{
				"traefik.http.routers.app1.rule": "Host(`app1.home.lab`)",
			},
		},
		{
			ID:    "app2-ctr",
			Names: []string{"/app2"},
			Image: "nginx",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{PrivatePort: 80, PublicPort: 8082, Type: "tcp"},
			},
			Labels: map[string]string{
				"traefik.http.routers.app2.rule": "Host(`app2.home.lab`)",
			},
		},
	}

	services := []protocol.DiscoveredWebService{
		{
			ID:          "svc-app1",
			Name:        "app1",
			URL:         "http://10.0.1.1:8081",
			Source:      "docker",
			ContainerID: "app1-ctr",
			HostAssetID: hostAssetID,
		},
		{
			ID:          "svc-app2",
			Name:        "app2",
			URL:         "http://10.0.1.1:8082",
			Source:      "docker",
			ContainerID: "app2-ctr",
			HostAssetID: hostAssetID,
		},
	}

	routes := []ProxyRoute{
		{
			Domain:     "app2.home.lab",
			BackendURL: "http://172.18.0.10:80",
			TLS:        true,
			RouterName: "app2",
		},
		{
			Domain:     "app1.home.lab",
			BackendURL: "",
			TLS:        false,
			RouterName: "app1",
		},
	}

	result := enrichServicesWithRoutes(services, routes, "traefik", hostAssetID, hostIP, containers)
	if len(result) != 2 {
		t.Fatalf("got %d services; want 2 (no proxy-only entries expected)", len(result))
	}

	var app1Svc *protocol.DiscoveredWebService
	var app2Svc *protocol.DiscoveredWebService
	for i := range result {
		if result[i].ContainerID == "app1-ctr" {
			app1Svc = &result[i]
		}
		if result[i].ContainerID == "app2-ctr" {
			app2Svc = &result[i]
		}
	}
	if app1Svc == nil || app2Svc == nil {
		t.Fatal("expected both app1 and app2 services")
	}

	if app2Svc.URL != "https://app2.home.lab" {
		t.Errorf("app2 URL = %q; want %q", app2Svc.URL, "https://app2.home.lab")
	}
	if app2Svc.Metadata["raw_url"] != "http://10.0.1.1:8082" {
		t.Errorf("app2 raw_url = %q; want %q", app2Svc.Metadata["raw_url"], "http://10.0.1.1:8082")
	}

	// Even without backend port, route can match via router label correlation.
	if app1Svc.URL != "http://app1.home.lab" {
		t.Errorf("app1 URL = %q; want %q", app1Svc.URL, "http://app1.home.lab")
	}
}
