package webservice

import (
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMatchHTMLFingerprint(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{"truenas root page", `<html><head><title>TrueNAS</title></head></html>`, "truenas"},
		{"truenas in body", `<html><body>Welcome to TrueNAS SCALE</body></html>`, "truenas"},
		{"synology dsm", `<html><head><title>Synology DiskStation</title></head></html>`, "synology"},
		{"synology keyword", `<html><body>Synology NAS</body></html>`, "synology"},
		{"diskstation keyword", `<html><body>DiskStation Manager</body></html>`, "synology"},
		{"qnap qts", `<html><body>QNAP Systems, Inc.</body></html>`, "qnap"},
		{"proxmox backup server", `<html><head><title>Proxmox Backup Server</title></head></html>`, "proxmox-backup"},
		{"proxmox ve", `<html><head><title>Proxmox Virtual Environment</title></head></html>`, "proxmox"},
		{"pve manager", `<html><body>PVE Manager</body></html>`, "proxmox"},
		{"pfsense", `<html><head><title>pfSense - Login</title></head></html>`, "pfsense"},
		{"opnsense", `<html><head><title>OPNsense - Login</title></head></html>`, "opnsense"},
		{"home assistant", `<html><body><home-assistant></home-assistant></body></html>`, "homeassistant"},
		{"pihole", `<html><head><title>Pi-hole Admin Console</title></head></html>`, "pihole"},
		{"unifi network", `<html><body>UniFi Network Application</body></html>`, "unifi"},
		{"cockpit ws", `<html><head><base href="/cockpit/@localhost/"></head></html>`, "cockpit"},
		{"unknown service", `<html><head><title>My App</title></head></html>`, ""},
		{"empty body", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchHTMLFingerprint([]byte(tt.html))
			if got != tt.want {
				t.Errorf("matchHTMLFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchHTMLFingerprintPBSBeforePVE(t *testing.T) {
	// PBS page should match "proxmox-backup" not "proxmox" even though both contain "proxmox".
	html := `<html><head><title>Proxmox Backup Server</title></head><body>Proxmox Backup Server Management</body></html>`
	got := matchHTMLFingerprint([]byte(html))
	if got != "proxmox-backup" {
		t.Errorf("PBS page matched %q, want %q", got, "proxmox-backup")
	}
}

func TestFingerprintByHTTPTrueNAS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>TrueNAS - Storage</title></head></html>`))
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
		Name: "Port 80", Category: CatOther, URL: server.URL, Source: "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "truenas" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "truenas")
	}
	if svc.Category != CatStorage {
		t.Fatalf("category = %q, want %q", svc.Category, CatStorage)
	}
}

func TestFingerprintByHTTPTrueNASRedirect(t *testing.T) {
	// TrueNAS redirects / to /ui/ — fingerprinting should follow the redirect target.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
		case "/ui/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>TrueNAS</title></head></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	wsc := &WebServiceCollector{
		client: &http.Client{
			Timeout:       2 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
		insecureClient: server.Client(),
	}
	svc := protocol.DiscoveredWebService{
		Name: "Port 80", Category: CatOther, URL: server.URL, Source: "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "truenas" {
		t.Fatalf("serviceKey = %q, want %q (redirect to /ui/ should be followed)", svc.ServiceKey, "truenas")
	}
}

func TestFingerprintByAPITrueNAS(t *testing.T) {
	// TrueNAS API returns 401 for unauthenticated requests but the endpoint exists.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>My NAS</title></head></html>`)) // no HTML marker
		case "/api/v2.0/system/version":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Not authenticated"}`))
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
		Name: "Port 80", Category: CatOther, URL: server.URL, Source: "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "truenas" {
		t.Fatalf("serviceKey = %q, want %q (API probe should match)", svc.ServiceKey, "truenas")
	}
}

func TestFingerprintByAPISynology(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" || r.URL.Path == "":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>NAS Login</title></head></html>`))
		case strings.HasPrefix(r.URL.Path, "/webapi/query.cgi"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"SYNO.API.Auth":{"maxVersion":7,"minVersion":1,"path":"auth.cgi"}},"success":true}`))
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
		Name: "Port 5000", Category: CatOther, URL: server.URL, Source: "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "synology" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "synology")
	}
}

func TestFingerprintByAPIQNAP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>NAS Login</title></head></html>`))
		case "/cgi-bin/authLogin.cgi":
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><QDocRoot><authSid>none</authSid><QNAP_SID/></QDocRoot>`))
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
		Name: "Port 8080", Category: CatOther, URL: server.URL, Source: "scan",
	}
	wsc.applyFingerprintMetadata(&svc)

	if svc.ServiceKey != "qnap" {
		t.Fatalf("serviceKey = %q, want %q", svc.ServiceKey, "qnap")
	}
}
