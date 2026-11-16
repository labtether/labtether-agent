package agentcore

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// hubCheck is the next server at the Hub's address, and whether the agent
// may talk to it.
type hubCheck struct {
	name     string
	tls      *tls.Config
	accepted bool
}

// Fault: after a late enrollment the agent kept the TLS settings it started
// with. Started with LABTETHER_TLS_SKIP_VERIFY=true and no CA file, it saved
// the CA the Hub returned but went on skipping certificate checks until it
// restarted, so a server with any certificate at the Hub's address received
// the agent token: on the WebSocket, in the HTTP heartbeat fallback and in
// update checks. Start-up enrollment trusts the saved CA at once.
//
// The other rows are the start-up cases the late path keeps; each fails if
// the late path trusts the Hub's CA where start-up does not: skip-verify
// stays when the Hub returns no CA (else the agent loses a Hub with a
// self-signed certificate), a CA file the person set wins (a TLS proxy in
// front of the Hub), and with LABTETHER_TLS_CA_ONLY the answer never
// replaces the pinned CA.
func TestLateEnrollmentTrustsTheHubCAFromTheNextConnection(t *testing.T) {
	hubCA := newTestAuthority(t, "Hub CA")
	otherCA := newTestAuthority(t, "Other CA")
	hubServer := hubCheck{"the Hub", hubCA.serverTLS(t), true}
	other := hubCheck{"a server with another CA", otherCA.serverTLS(t), false}
	trusted := func(check hubCheck) hubCheck { check.accepted = true; return check }

	cases := []struct {
		name     string
		env      func(dir string) map[string]string
		answerCA []byte // the CA in the enrollment answer
		savedCA  []byte // ca.crt afterwards; nil: none
		then     []hubCheck
	}{
		{
			name:     "skip-verify, the Hub returns its CA",
			env:      func(string) map[string]string { return map[string]string{"LABTETHER_TLS_SKIP_VERIFY": "true"} },
			answerCA: hubCA.pem(), savedCA: hubCA.pem(),
			then: []hubCheck{other, hubServer},
		},
		{
			name: "skip-verify, no CA in the answer",
			env:  func(string) map[string]string { return map[string]string{"LABTETHER_TLS_SKIP_VERIFY": "true"} },
			then: []hubCheck{trusted(other)},
		},
		{
			name: "a CA file the person set wins",
			env: func(dir string) map[string]string {
				return map[string]string{"LABTETHER_TLS_SKIP_VERIFY": "true", "LABTETHER_TLS_CA_FILE": writeCA(t, dir, "proxy-ca.crt", hubCA.pem())}
			},
			answerCA: otherCA.pem(),
			then:     []hubCheck{other, hubServer},
		},
		{
			name: "CA-only keeps the pinned CA",
			env: func(dir string) map[string]string {
				return map[string]string{envTLSCAOnly: "true", "LABTETHER_TLS_CA_FILE": writeCA(t, dir, "ca.crt", hubCA.pem())}
			},
			answerCA: otherCA.pem(), savedCA: hubCA.pem(),
			then: []hubCheck{other, hubServer},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hub, dir, _ := lateHubAgent(t)
			hub.secure, hub.caPEM = true, string(tc.answerCA)
			hub.enrollStatus.Store(http.StatusOK)
			t.Setenv("LABTETHER_WS_URL", hub.wsURL())
			for name, value := range tc.env(dir) {
				t.Setenv(name, value)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg, transport, fallback := startAgentWithoutHub(t, ctx, hub, dir)

			waits := 0
			transport.timeAfter = func(time.Duration) <-chan time.Time {
				if waits++; waits == 1 {
					hub.serve(hubServer.tls)
				} else if waits > 20 {
					cancel()
				}
				ready := make(chan time.Time, 1)
				ready <- time.Now()
				return ready
			}
			runLoopUntilStopped(t, ctx, cancel, transport)
			if _, pending, authorized := hub.seen(); pending != 0 || strings.Join(authorized, ",") != "Bearer issued-agent-token" {
				t.Fatalf("after the late enrollment: pending sockets=%d sockets with a token=%q", pending, authorized)
			}
			if saved, _ := os.ReadFile(filepath.Join(dir, "ca.crt")); string(saved) != string(tc.savedCA) {
				t.Fatalf("ca.crt = %q, want %q", saved, tc.savedCA)
			}

			for _, check := range tc.then {
				hub.stop()
				hub.serve(check.tls)
				_, _, before := hub.seen()
				for consumer, err := range hubConnections(hub, cfg, transport, fallback) {
					if check.accepted && err != nil {
						t.Errorf("%s: %s was refused: %v", consumer, check.name, err)
					}
					if !check.accepted && (err == nil || !strings.Contains(err.Error(), "certificate")) {
						t.Errorf("%s: %s was not refused for its certificate: %v", consumer, check.name, err)
					}
				}
				hub.mu.Lock()
				requests := len(hub.requests)
				hub.requests = nil
				hub.mu.Unlock()
				if _, _, after := hub.seen(); !check.accepted && (len(after) != len(before) || requests != 0) {
					t.Errorf("%s was reached: %d sockets with a token, %d requests", check.name, len(after)-len(before), requests)
				}
			}
		})
	}
}

// hubConnections opens each connection to the Hub the agent makes with its
// token, the way the running agent makes it, and returns each one's error.
func hubConnections(hub *lateHub, cfg RuntimeConfig, transport *wsTransport, fallback HeartbeatPublisher) map[string]error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := map[string]error{}
	results["websocket"] = transport.Connect(ctx)
	transport.markDisconnected()
	results["heartbeat fallback"] = fallback.Publish(ctx, TelemetrySample{AssetID: "nas01"})
	// The update check is built from the configuration handlers get.
	req, err := securityruntime.NewOutboundRequestWithContext(ctx, http.MethodGet, hub.apiURL()+"/api/v1/agent/releases/latest", nil)
	if err == nil {
		var resp *http.Response
		resp, err = securityruntime.DoOutboundRequest(newSelfUpdateHTTPClient(runtimeConfigWithCurrentIdentity(cfg, transport)), req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}
	results["update check"] = err
	return results
}

func writeCA(t *testing.T, dir, name string, pem []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
