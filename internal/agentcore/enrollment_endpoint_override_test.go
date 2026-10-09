package agentcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistedEnrollmentEndpointsRespectCompleteHubOverride(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	if err := saveEnrollmentState(tokenFile, enrollmentState{
		AssetID: "canonical-node", HubWSURL: "wss://old-ws.test:8443/custom/ws/agent",
		HubAPIURL: "https://old-api.test:9443",
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, ws, api, wantWS, wantAPI string
	}{
		{"saved pair", "", "", "wss://old-ws.test:8443/custom/ws/agent", "https://old-api.test:9443"},
		{"WS only", "wss://new-ws.test:8443/ws/agent", "", "wss://new-ws.test:8443/ws/agent", "https://new-ws.test:8443"},
		{"API only", "", "https://new-api.test:8443", "wss://new-api.test:8443/custom/ws/agent", "https://new-api.test:8443"},
		{"explicit split", "wss://new-ws.test:8443/ws/agent", "https://new-api.test:9443", "wss://new-ws.test:8443/ws/agent", "https://new-api.test:9443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := RuntimeConfig{TokenFilePath: tokenFile, AssetID: "stale-name", WSBaseURL: tc.ws, APIBaseURL: tc.api}
			if err := restoreEnrollmentState(&cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.AssetID != "canonical-node" || cfg.WSBaseURL != tc.wantWS || cfg.APIBaseURL != tc.wantAPI {
				t.Fatalf("restored asset=%q ws=%q api=%q; want asset=%q ws=%q api=%q",
					cfg.AssetID, cfg.WSBaseURL, cfg.APIBaseURL, "canonical-node", tc.wantWS, tc.wantAPI)
			}
		})
	}
}

func TestEnrollmentPreservesOperatorTLSCAForProxy(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	dir := t.TempDir()
	operatorCA := filepath.Join(dir, "proxy-ca.pem")
	operatorPEM := testCACertPEM(t)
	if err := os.WriteFile(operatorCA, []byte(operatorPEM), 0644); err != nil {
		t.Fatal(err)
	}
	returnedPEM := testCACertPEM(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(enrollResponse{
			AgentToken: "issued-token", AssetID: "qa-node", CACertPEM: returnedPEM,
		})
	}))
	defer server.Close()
	cfg := RuntimeConfig{
		AssetID: "qa-node", APIBaseURL: server.URL, EnrollmentToken: "one-use-token",
		TokenFilePath: filepath.Join(dir, "agent-token"), TLSCAFile: operatorCA,
	}
	if err := ResolveToken(context.Background(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCAFile != operatorCA {
		t.Fatalf("configured CA was replaced by enrollment CA: %q", cfg.TLSCAFile)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); !os.IsNotExist(err) {
		t.Fatalf("internal CA was saved over explicit trust: %v", err)
	}
}
