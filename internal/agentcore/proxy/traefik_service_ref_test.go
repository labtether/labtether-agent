package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// traefikTestdataVersions are real Traefik API answers (testdata/traefik/),
// recorded from one Traefik with the file and Docker providers: file
// routers with a bare service ("f1"), with their own provider written out
// ("f1@file") and with a Docker service ("d1@docker"); Docker routers from
// labels ("d1") and from the default rule ("ltqa-tsp-d2"). routes.json is
// the route list for them, each backend the server Traefik itself sends
// that host to. The Rust agent's tests read the same files.
var traefikTestdataVersions = []string{"v3.7.19", "v2.11.63"}

type traefikExpectedRoute struct {
	Domain     string `json:"domain"`
	BackendURL string `json:"backend_url"`
	TLS        bool   `json:"tls"`
	RouterName string `json:"router_name"`
}

// Fault: the routers list gives a service in the router's own provider by
// its bare name ("f1" for router "f1@file") while the services list names
// it "f1@file". Looked up by the bare name, 7 of these 9 routes lost their
// backend, so each became a service of its own instead of joining the
// service it proxies.
func TestTraefikFetchRoutesQualifiesBareServiceWithRouterProvider(t *testing.T) {
	for _, version := range traefikTestdataVersions {
		t.Run(version, func(t *testing.T) {
			dir := filepath.Join("testdata", "traefik", version)
			routers := readTraefikTestdata(t, dir, "routers.json")
			services := readTraefikTestdata(t, dir, "services.json")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/http/routers":
					_, _ = w.Write(routers)
				case "/api/http/services":
					_, _ = w.Write(services)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			routes, err := NewTraefikProvider().FetchRoutes(srv.URL)
			if err != nil {
				t.Fatalf("FetchRoutes: %v", err)
			}
			got := make([]traefikExpectedRoute, 0, len(routes))
			for _, route := range routes {
				got = append(got, traefikExpectedRoute{route.Domain, route.BackendURL, route.TLS, route.RouterName})
			}
			var want []traefikExpectedRoute
			if err := json.Unmarshal(readTraefikTestdata(t, dir, "routes.json"), &want); err != nil {
				t.Fatalf("routes.json: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("routes:\n got  %+v\n want %+v", got, want)
			}
		})
	}
}

func readTraefikTestdata(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
