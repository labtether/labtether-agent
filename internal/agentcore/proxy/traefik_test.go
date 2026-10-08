package proxy

import (
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"testing"
)

// ---------------------------------------------------------------------------
// TestTraefikProviderName
// ---------------------------------------------------------------------------

func TestTraefikProviderName(t *testing.T) {
	p := NewTraefikProvider()
	if p.Name() != "traefik" {
		t.Errorf("Name() = %q; want %q", p.Name(), "traefik")
	}
}

// ---------------------------------------------------------------------------
// TestTraefikDetectAndConnect
// ---------------------------------------------------------------------------

func TestTraefikDetectAndConnect(t *testing.T) {
	t.Run("detects traefik with API port exposed", func(t *testing.T) {
		containers := []dockerpkg.DockerContainer{
			{
				ID:    "traefik-123",
				Names: []string{"/traefik"},
				Image: "traefik:v3.0",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 80, PublicPort: 80, Type: "tcp"},
					{PrivatePort: 8080, PublicPort: 8080, Type: "tcp"},
				},
			},
		}

		p := NewTraefikProvider()
		apiURL, ok := p.DetectAndConnect(containers)
		if !ok {
			t.Fatal("DetectAndConnect returned false; want true")
		}
		if apiURL != "http://localhost:8080" {
			t.Errorf("apiURL = %q; want %q", apiURL, "http://localhost:8080")
		}
	})

	t.Run("detects traefik with remapped API port", func(t *testing.T) {
		containers := []dockerpkg.DockerContainer{
			{
				ID:    "traefik-456",
				Names: []string{"/traefik"},
				Image: "docker.io/library/traefik:latest",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 80, PublicPort: 80, Type: "tcp"},
					{PrivatePort: 8080, PublicPort: 9999, Type: "tcp"},
				},
			},
		}

		p := NewTraefikProvider()
		apiURL, ok := p.DetectAndConnect(containers)
		if !ok {
			t.Fatal("DetectAndConnect returned false; want true")
		}
		if apiURL != "http://localhost:9999" {
			t.Errorf("apiURL = %q; want %q", apiURL, "http://localhost:9999")
		}
	})

	t.Run("falls back to dashboard host rule when API port not exposed", func(t *testing.T) {
		containers := []dockerpkg.DockerContainer{
			{
				ID:    "traefik-dashboard",
				Names: []string{"/traefik"},
				Image: "traefik:v3.0",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 80, PublicPort: 80, Type: "tcp"},
					{PrivatePort: 443, PublicPort: 443, Type: "tcp"},
				},
				Labels: map[string]string{
					"traefik.http.routers.dashboard.rule":        "Host(`dashboard.example.com`)",
					"traefik.http.routers.dashboard.entrypoints": "websecure",
					"traefik.http.routers.dashboard.service":     "api@internal",
				},
			},
		}

		p := NewTraefikProvider()
		apiURL, ok := p.DetectAndConnect(containers)
		if !ok {
			t.Fatal("DetectAndConnect returned false; want true from dashboard label fallback")
		}
		if apiURL != "https://dashboard.example.com" {
			t.Errorf("apiURL = %q; want %q", apiURL, "https://dashboard.example.com")
		}
	})

	t.Run("dashboard fallback prefers http when tls hints absent", func(t *testing.T) {
		containers := []dockerpkg.DockerContainer{
			{
				ID:    "traefik-dashboard-http",
				Names: []string{"/traefik"},
				Image: "traefik:v3.0",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 80, PublicPort: 80, Type: "tcp"},
				},
				Labels: map[string]string{
					"traefik.http.routers.dashboard.rule":    "Host(`dashboard-http.example.com`)",
					"traefik.http.routers.dashboard.service": "api@internal",
				},
			},
		}

		p := NewTraefikProvider()
		apiURL, ok := p.DetectAndConnect(containers)
		if !ok {
			t.Fatal("DetectAndConnect returned false; want true from dashboard label fallback")
		}
		if apiURL != "http://dashboard-http.example.com" {
			t.Errorf("apiURL = %q; want %q", apiURL, "http://dashboard-http.example.com")
		}
	})

	t.Run("skips when API port not exposed", func(t *testing.T) {
		containers := []dockerpkg.DockerContainer{
			{
				ID:    "traefik-789",
				Names: []string{"/traefik"},
				Image: "traefik:v3.0",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 80, PublicPort: 80, Type: "tcp"},
					{PrivatePort: 8080, PublicPort: 0, Type: "tcp"},
				},
			},
		}

		p := NewTraefikProvider()
		_, ok := p.DetectAndConnect(containers)
		if ok {
			t.Error("DetectAndConnect returned true; want false (API port not exposed)")
		}
	})

	t.Run("skips non-traefik containers", func(t *testing.T) {
		containers := []dockerpkg.DockerContainer{
			{
				ID:    "nginx-123",
				Names: []string{"/nginx"},
				Image: "nginx:latest",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 80, PublicPort: 80, Type: "tcp"},
					{PrivatePort: 8080, PublicPort: 8080, Type: "tcp"},
				},
			},
			{
				ID:    "plex-456",
				Names: []string{"/plex"},
				Image: "linuxserver/plex",
				State: "running",
				Ports: []dockerpkg.DockerPort{
					{PrivatePort: 32400, PublicPort: 32400, Type: "tcp"},
				},
			},
		}

		p := NewTraefikProvider()
		_, ok := p.DetectAndConnect(containers)
		if ok {
			t.Error("DetectAndConnect returned true; want false (no traefik container)")
		}
	})

	t.Run("empty containers list", func(t *testing.T) {
		p := NewTraefikProvider()
		_, ok := p.DetectAndConnect(nil)
		if ok {
			t.Error("DetectAndConnect returned true; want false (no containers)")
		}
	})
}

// ---------------------------------------------------------------------------
// TestExtractHostFromRule
// ---------------------------------------------------------------------------

func TestExtractHostsFromRule(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want []string
	}{
		{
			name: "standard Host rule",
			rule: "Host(`plex.home.lab`)",
			want: []string{"plex.home.lab"},
		},
		{
			name: "Host with path prefix",
			rule: "Host(`app.home.lab`) && PathPrefix(`/api`)",
			want: []string{"app.home.lab"},
		},
		{
			name: "Host with multiple conditions",
			rule: "Host(`grafana.home.lab`) && Headers(`X-Custom`, `value`)",
			want: []string{"grafana.home.lab"},
		},
		{
			name: "multi-host OR rule",
			rule: "Host(`a.home.lab`) || Host(`b.home.lab`)",
			want: []string{"a.home.lab", "b.home.lab"},
		},
		{
			name: "no Host rule",
			rule: "PathPrefix(`/api`)",
			want: nil,
		},
		{
			name: "empty rule",
			rule: "",
			want: nil,
		},
		{
			name: "Host with subdomain",
			rule: "Host(`sub.domain.example.com`)",
			want: []string{"sub.domain.example.com"},
		},
		{
			name: "HostSNI rule (should not match Host pattern)",
			rule: "HostSNI(`*`)",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHostsFromRule(tt.rule)
			if len(got) != len(tt.want) {
				t.Errorf("extractHostsFromRule(%q) = %v; want %v", tt.rule, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractHostsFromRule(%q)[%d] = %q; want %q", tt.rule, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestIsTraefikInternal
// ---------------------------------------------------------------------------

func TestIsTraefikInternal(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"api@internal", true},
		{"dashboard@internal", true},
		{"noop@internal", true},
		{"plex@docker", false},
		{"app@file", false},
		{"internal", false},
		{"my-internal-app@docker", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTraefikInternal(tt.name)
			if got != tt.want {
				t.Errorf("isTraefikInternal(%q) = %v; want %v", tt.name, got, tt.want)
			}
		})
	}
}
