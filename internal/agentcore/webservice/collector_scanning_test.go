package webservice

import (
	"context"
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"reflect"
	"strconv"
	"testing"
)

func TestParsePortList(t *testing.T) {
	got := parsePortList(" 8080,443;8080 bad 65536 0 80 +3000 3000abc ")
	want := []int{80, 443, 8080}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePortList() = %v, want %v", got, want)
	}
}

func TestParseProcNetListeningPorts(t *testing.T) {
	raw := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0568 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0035 00000000:0000 01 00000000:00000000 00:00000000 00000000   100        0 34567 1 0000000000000000 100 0 0 10 0
`

	got := parseProcNetListeningPorts(raw)
	want := []int{8080, 1384}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseProcNetListeningPorts() = %v, want %v", got, want)
	}
}

func TestScanCandidatePortsCanDisableListeningAugment(t *testing.T) {
	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_PORTS", "9010,9011")
	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_INCLUDE_LISTENING", "false")

	got := scanCandidatePorts()
	want := []int{9010, 9011}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scanCandidatePorts() = %v, want %v", got, want)
	}
}

func TestDiscoverPortScannedServices(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	parsed, err := neturl.Parse(httpServer.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_DISABLED", "false")
	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_PORTS", strconv.Itoa(port))
	// Disable listening-port discovery so /proc/net/tcp on Linux CI does not
	// inject extra candidate ports that may be reachable and break the count.
	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_INCLUDE_LISTENING", "false")

	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	services := wsc.discoverPortScannedServices(context.Background(), nil)
	if len(services) != 1 {
		t.Fatalf("discoverPortScannedServices() returned %d services, want 1", len(services))
	}
	if services[0].Source != "scan" {
		t.Fatalf("service source = %q, want scan", services[0].Source)
	}
	if services[0].Metadata["public_port"] != strconv.Itoa(port) {
		t.Fatalf("public_port metadata = %q, want %d", services[0].Metadata["public_port"], port)
	}

	alreadyKnown := []protocol.DiscoveredWebService{
		{
			URL: buildServiceURL("127.0.0.1", port),
		},
	}
	services = wsc.discoverPortScannedServices(context.Background(), alreadyKnown)
	if len(services) != 0 {
		t.Fatalf("discoverPortScannedServices() returned %d services with existing port, want 0", len(services))
	}
}

func TestDiscoverPortScannedServicesSkipsPortsFromServiceMetadata(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	parsed, err := neturl.Parse(httpServer.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_DISABLED", "false")
	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_PORTS", strconv.Itoa(port))
	t.Setenv("LABTETHER_WEBSVC_PORTSCAN_INCLUDE_LISTENING", "false")

	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
	}

	alreadyKnown := []protocol.DiscoveredWebService{
		{
			URL: "https://plex.home.lab",
			Metadata: map[string]string{
				"backend_url": "http://127.0.0.1:" + strconv.Itoa(port),
				"public_port": strconv.Itoa(port),
			},
		},
	}

	services := wsc.discoverPortScannedServices(context.Background(), alreadyKnown)
	if len(services) != 0 {
		t.Fatalf("discoverPortScannedServices() returned %d services with metadata-known port, want 0", len(services))
	}
}

func TestDiscoverLANScannedServices(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	parsed, err := neturl.Parse(httpServer.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	wsc := &WebServiceCollector{
		assetID: "asset-1",
		hostIP:  "127.0.0.1",
		discoveryCfg: WebServiceDiscoveryConfig{
			LANScanEnabled:  true,
			LANScanCIDRs:    "127.0.0.1/32",
			LANScanPorts:    strconv.Itoa(port),
			LANScanMaxHosts: 8,
		},
	}

	services := wsc.discoverLANScannedServices(context.Background(), nil)
	if len(services) != 1 {
		t.Fatalf("discoverLANScannedServices() returned %d services, want 1", len(services))
	}
	if services[0].Source != "scan" {
		t.Fatalf("service source = %q, want scan", services[0].Source)
	}
	if services[0].Metadata["scan_scope"] != "lan" {
		t.Fatalf("scan_scope metadata = %q, want lan", services[0].Metadata["scan_scope"])
	}
	if services[0].Metadata["scan_target_host"] != "127.0.0.1" {
		t.Fatalf("scan_target_host metadata = %q, want 127.0.0.1", services[0].Metadata["scan_target_host"])
	}

	alreadyKnown := []protocol.DiscoveredWebService{
		{
			URL: buildServiceURL("127.0.0.1", port),
		},
	}
	services = wsc.discoverLANScannedServices(context.Background(), alreadyKnown)
	if len(services) != 0 {
		t.Fatalf("discoverLANScannedServices() returned %d services with existing endpoint, want 0", len(services))
	}
}

func TestScannedPortMetadataAmbiguousPortUsesGenericValues(t *testing.T) {
	if _, found := LookupByPort(3000); !found {
		t.Fatal("expected legacy LookupByPort(3000) match for ambiguous-port precondition")
	}
	if _, found := LookupUniqueByPort(3000); found {
		t.Fatal("expected unique lookup for port 3000 to be unresolved")
	}

	name, category, iconKey, serviceKey, healthPath, known := scannedPortMetadata(3000)
	if known {
		t.Fatal("expected ambiguous port metadata to be treated as unknown")
	}
	if name != "Port 3000" {
		t.Fatalf("name = %q, want %q", name, "Port 3000")
	}
	if category != CatOther {
		t.Fatalf("category = %q, want %q", category, CatOther)
	}
	if iconKey != "" {
		t.Fatalf("iconKey = %q, want empty", iconKey)
	}
	if serviceKey != "" {
		t.Fatalf("serviceKey = %q, want empty", serviceKey)
	}
	if healthPath != "" {
		t.Fatalf("healthPath = %q, want empty", healthPath)
	}
}
