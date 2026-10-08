package webservice

import (
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"testing"
)

func TestBuildServicesFromContainersIncludesImageMetadata(t *testing.T) {
	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	containers := []dockerpkg.DockerContainer{
		{
			ID:    "abc123def4567890",
			Names: []string{"/grafana"},
			Image: "grafana/grafana:latest",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{IP: "0.0.0.0", PrivatePort: 3000, PublicPort: 3000, Type: "tcp"},
			},
		},
	}

	services := wsc.buildServicesFromContainers(containers)
	if len(services) != 1 {
		t.Fatalf("buildServicesFromContainers() returned %d services, want 1", len(services))
	}

	if services[0].Source != "docker" {
		t.Fatalf("source = %q, want docker", services[0].Source)
	}
	if services[0].Metadata == nil {
		t.Fatal("expected metadata to be present")
	}
	if services[0].Metadata["image"] != "grafana/grafana:latest" {
		t.Fatalf("image metadata = %q, want %q", services[0].Metadata["image"], "grafana/grafana:latest")
	}
}

func TestBuildServicesFromContainersClassifiesByContainerNameHint(t *testing.T) {
	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	containers := []dockerpkg.DockerContainer{
		{
			ID:    "abc123def4567890",
			Names: []string{"/my_grafana_1"},
			Image: "registry.local/custom/grafana-build:latest",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{IP: "0.0.0.0", PrivatePort: 3000, PublicPort: 3000, Type: "tcp"},
			},
		},
	}

	services := wsc.buildServicesFromContainers(containers)
	if len(services) != 1 {
		t.Fatalf("buildServicesFromContainers() returned %d services, want 1", len(services))
	}
	if services[0].ServiceKey != "grafana" {
		t.Fatalf("service key = %q, want %q", services[0].ServiceKey, "grafana")
	}
	if services[0].Name != "Grafana" {
		t.Fatalf("name = %q, want %q", services[0].Name, "Grafana")
	}
	if services[0].Category != CatMonitoring {
		t.Fatalf("category = %q, want %q", services[0].Category, CatMonitoring)
	}
}

func TestCleanContainerName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"strips leading slash", "/plex", "plex"},
		{"no slash unchanged", "grafana", "grafana"},
		{"empty string", "", ""},
		{"only slash", "/", ""},
		{"nested path preserved", "/compose/service", "compose/service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanContainerName(tt.input)
			if got != tt.want {
				t.Errorf("cleanContainerName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildServicesFromContainersReadsLabTetherLabels(t *testing.T) {
	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	containers := []dockerpkg.DockerContainer{
		{
			ID:    "abc123def4567890",
			Names: []string{"/custom-app"},
			Image: "my-private/custom-app:latest",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{IP: "0.0.0.0", PrivatePort: 8080, PublicPort: 8080, Type: "tcp"},
			},
			Labels: map[string]string{
				"labtether.category": "Productivity",
				"labtether.icon":     "custom-app",
				"labtether.name":     "My Custom App",
			},
		},
	}

	services := wsc.buildServicesFromContainers(containers)
	if len(services) != 1 {
		t.Fatalf("got %d services, want 1", len(services))
	}

	svc := services[0]
	if svc.Name != "My Custom App" {
		t.Errorf("name = %q, want %q", svc.Name, "My Custom App")
	}
	if svc.Category != "Productivity" {
		t.Errorf("category = %q, want %q", svc.Category, "Productivity")
	}
	if svc.IconKey != "custom-app" {
		t.Errorf("icon_key = %q, want %q", svc.IconKey, "custom-app")
	}
}

func TestBuildServicesFromContainersLabTetherHiddenLabel(t *testing.T) {
	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	containers := []dockerpkg.DockerContainer{
		{
			ID:    "abc123def4567890",
			Names: []string{"/hidden-app"},
			Image: "some/app:latest",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{IP: "0.0.0.0", PrivatePort: 9090, PublicPort: 9090, Type: "tcp"},
			},
			Labels: map[string]string{
				"labtether.hidden": "true",
			},
		},
	}

	services := wsc.buildServicesFromContainers(containers)
	if len(services) != 1 {
		t.Fatalf("got %d services, want 1", len(services))
	}
	if services[0].Metadata == nil || services[0].Metadata["hidden"] != "true" {
		t.Errorf("expected hidden metadata to be 'true', got %v", services[0].Metadata)
	}
}

func TestBuildServicesFromContainersLabTetherLabelsOverrideAutoDetection(t *testing.T) {
	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	// Grafana is auto-detected as Monitoring, but label overrides to Development
	containers := []dockerpkg.DockerContainer{
		{
			ID:    "abc123def4567890",
			Names: []string{"/grafana"},
			Image: "grafana/grafana:latest",
			State: "running",
			Ports: []dockerpkg.DockerPort{
				{IP: "0.0.0.0", PrivatePort: 3000, PublicPort: 3000, Type: "tcp"},
			},
			Labels: map[string]string{
				"labtether.category": "Development",
				"labtether.name":     "Dev Grafana",
			},
		},
	}

	services := wsc.buildServicesFromContainers(containers)
	if len(services) != 1 {
		t.Fatalf("got %d services, want 1", len(services))
	}
	if services[0].Category != "Development" {
		t.Errorf("category = %q, want %q", services[0].Category, "Development")
	}
	if services[0].Name != "Dev Grafana" {
		t.Errorf("name = %q, want %q", services[0].Name, "Dev Grafana")
	}
	// Icon should still be grafana since no label override was set for icon
	if services[0].IconKey != "grafana" {
		t.Errorf("icon_key = %q, want %q", services[0].IconKey, "grafana")
	}
}

func TestExtractTraefikURL(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			"standard traefik v2 rule",
			map[string]string{
				"traefik.http.routers.plex.rule": "Host(`plex.example.com`)",
			},
			"https://plex.example.com",
		},
		{
			"no traefik labels",
			map[string]string{
				"com.docker.compose.project": "mystack",
			},
			"",
		},
		{
			"nil labels",
			nil,
			"",
		},
		{
			"traefik label without Host rule",
			map[string]string{
				"traefik.http.routers.myapp.entrypoints": "websecure",
			},
			"",
		},
		{
			"complex host rule with path",
			map[string]string{
				"traefik.http.routers.grafana.rule": "Host(`grafana.home.lan`) && PathPrefix(`/`)",
			},
			"https://grafana.home.lan",
		},
		{
			"empty labels map",
			map[string]string{},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTraefikURL(tt.labels)
			if got != tt.want {
				t.Errorf("extractTraefikURL(%v) = %q, want %q", tt.labels, got, tt.want)
			}
		})
	}
}
