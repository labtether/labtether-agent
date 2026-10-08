package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// TestTraefikFetchRoutes
// ---------------------------------------------------------------------------

func TestTraefikFetchRoutes(t *testing.T) {
	t.Run("fetches and parses routes correctly", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "plex@docker",
				Rule:        "Host(`plex.home.lab`)",
				Service:     "plex-svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"websecure"},
			},
			{
				Name:        "sonarr@docker",
				Rule:        "Host(`sonarr.home.lab`)",
				Service:     "sonarr-svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"web"},
			},
		}

		services := []traefikServiceItem{
			{
				Name: "plex-svc@docker",
				LoadBalancer: &traefikLoadBalancer{
					Servers: []traefikServer{
						{URL: "http://172.18.0.5:32400"},
					},
				},
			},
			{
				Name: "sonarr-svc@docker",
				LoadBalancer: &traefikLoadBalancer{
					Servers: []traefikServer{
						{URL: "http://172.18.0.6:8989"},
					},
				},
			},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 2 {
			t.Fatalf("got %d routes; want 2", len(routes))
		}

		// Check plex route.
		plex := routes[0]
		if plex.Domain != "plex.home.lab" {
			t.Errorf("plex domain = %q; want %q", plex.Domain, "plex.home.lab")
		}
		if plex.BackendURL != "http://172.18.0.5:32400" {
			t.Errorf("plex backend = %q; want %q", plex.BackendURL, "http://172.18.0.5:32400")
		}
		if !plex.TLS {
			t.Error("plex TLS = false; want true (websecure entrypoint)")
		}
		if plex.RouterName != "plex" {
			t.Errorf("plex router name = %q; want %q", plex.RouterName, "plex")
		}

		// Check sonarr route.
		sonarr := routes[1]
		if sonarr.Domain != "sonarr.home.lab" {
			t.Errorf("sonarr domain = %q; want %q", sonarr.Domain, "sonarr.home.lab")
		}
		if sonarr.BackendURL != "http://172.18.0.6:8989" {
			t.Errorf("sonarr backend = %q; want %q", sonarr.BackendURL, "http://172.18.0.6:8989")
		}
		if sonarr.TLS {
			t.Error("sonarr TLS = true; want false (web entrypoint)")
		}
		if sonarr.RouterName != "sonarr" {
			t.Errorf("sonarr router name = %q; want %q", sonarr.RouterName, "sonarr")
		}
	})

	t.Run("filters @internal routes", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "api@internal",
				Rule:        "PathPrefix(`/api`)",
				Service:     "api@internal",
				Status:      "enabled",
				EntryPoints: []string{"traefik"},
			},
			{
				Name:        "dashboard@internal",
				Rule:        "PathPrefix(`/dashboard`)",
				Service:     "dashboard@internal",
				Status:      "enabled",
				EntryPoints: []string{"traefik"},
			},
			{
				Name:        "real-app@docker",
				Rule:        "Host(`app.home.lab`)",
				Service:     "app-svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"websecure"},
			},
		}

		services := []traefikServiceItem{
			{
				Name: "app-svc@docker",
				LoadBalancer: &traefikLoadBalancer{
					Servers: []traefikServer{
						{URL: "http://172.18.0.10:3000"},
					},
				},
			},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("got %d routes; want 1 (@internal should be filtered)", len(routes))
		}

		if routes[0].RouterName != "real-app" {
			t.Errorf("route name = %q; want %q", routes[0].RouterName, "real-app")
		}
	})

	t.Run("filters disabled routes", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "disabled-app@docker",
				Rule:        "Host(`disabled.home.lab`)",
				Service:     "disabled-svc@docker",
				Status:      "disabled",
				EntryPoints: []string{"websecure"},
			},
			{
				Name:        "enabled-app@docker",
				Rule:        "Host(`enabled.home.lab`)",
				Service:     "enabled-svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"web"},
			},
		}

		services := []traefikServiceItem{
			{
				Name: "enabled-svc@docker",
				LoadBalancer: &traefikLoadBalancer{
					Servers: []traefikServer{
						{URL: "http://172.18.0.20:8080"},
					},
				},
			},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("got %d routes; want 1 (disabled should be filtered)", len(routes))
		}

		if routes[0].Domain != "enabled.home.lab" {
			t.Errorf("route domain = %q; want %q", routes[0].Domain, "enabled.home.lab")
		}
	})

	t.Run("TLS detection from entrypoints", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "https-ep@docker",
				Rule:        "Host(`https-ep.home.lab`)",
				Service:     "svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"https"},
			},
			{
				Name:        "tls-ep@docker",
				Rule:        "Host(`tls-ep.home.lab`)",
				Service:     "svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"tls"},
			},
			{
				Name:        "websecure-ep@docker",
				Rule:        "Host(`ws-ep.home.lab`)",
				Service:     "svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"websecure"},
			},
			{
				Name:        "http-only@docker",
				Rule:        "Host(`http.home.lab`)",
				Service:     "svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"web"},
			},
		}

		services := []traefikServiceItem{
			{
				Name: "svc@docker",
				LoadBalancer: &traefikLoadBalancer{
					Servers: []traefikServer{
						{URL: "http://172.18.0.30:8080"},
					},
				},
			},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 4 {
			t.Fatalf("got %d routes; want 4", len(routes))
		}

		// https entrypoint -> TLS
		if !routes[0].TLS {
			t.Error("https-ep TLS = false; want true")
		}
		// tls entrypoint -> TLS
		if !routes[1].TLS {
			t.Error("tls-ep TLS = false; want true")
		}
		// websecure entrypoint -> TLS
		if !routes[2].TLS {
			t.Error("websecure-ep TLS = false; want true")
		}
		// web entrypoint -> no TLS
		if routes[3].TLS {
			t.Error("http-only TLS = true; want false")
		}
	})

	t.Run("TLS detection from TLS config field", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "tls-config@docker",
				Rule:        "Host(`tls-config.home.lab`)",
				Service:     "svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"web"},
				TLS:         &struct{}{},
			},
		}

		services := []traefikServiceItem{
			{
				Name: "svc@docker",
				LoadBalancer: &traefikLoadBalancer{
					Servers: []traefikServer{
						{URL: "http://172.18.0.40:8080"},
					},
				},
			},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("got %d routes; want 1", len(routes))
		}

		if !routes[0].TLS {
			t.Error("TLS = false; want true (TLS config present)")
		}
	})

	t.Run("handles no backend URL gracefully", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "no-backend@docker",
				Rule:        "Host(`nb.home.lab`)",
				Service:     "missing-svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"websecure"},
			},
		}

		// No matching service in services list.
		services := []traefikServiceItem{}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("got %d routes; want 1", len(routes))
		}

		if routes[0].BackendURL != "" {
			t.Errorf("backend URL = %q; want empty", routes[0].BackendURL)
		}
	})

	t.Run("strips provider suffix from router name", func(t *testing.T) {
		routers := []traefikRouter{
			{
				Name:        "plex-router@docker",
				Rule:        "Host(`plex.home.lab`)",
				Service:     "plex-svc@docker",
				Status:      "enabled",
				EntryPoints: []string{"web"},
			},
			{
				Name:        "simple-name@file",
				Rule:        "Host(`simple.home.lab`)",
				Service:     "simple-svc@file",
				Status:      "enabled",
				EntryPoints: []string{"web"},
			},
			{
				Name:        "no-suffix",
				Rule:        "Host(`nosuffix.home.lab`)",
				Service:     "nosuffix-svc",
				Status:      "enabled",
				EntryPoints: []string{"web"},
			},
		}

		services := []traefikServiceItem{}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/http/routers":
				json.NewEncoder(w).Encode(routers)
			case "/api/http/services":
				json.NewEncoder(w).Encode(services)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		p := NewTraefikProvider()
		routes, err := p.FetchRoutes(srv.URL)
		if err != nil {
			t.Fatalf("FetchRoutes returned error: %v", err)
		}

		if len(routes) != 3 {
			t.Fatalf("got %d routes; want 3", len(routes))
		}

		if routes[0].RouterName != "plex-router" {
			t.Errorf("route[0] name = %q; want %q", routes[0].RouterName, "plex-router")
		}
		if routes[1].RouterName != "simple-name" {
			t.Errorf("route[1] name = %q; want %q", routes[1].RouterName, "simple-name")
		}
		if routes[2].RouterName != "no-suffix" {
			t.Errorf("route[2] name = %q; want %q", routes[2].RouterName, "no-suffix")
		}
	})
}
