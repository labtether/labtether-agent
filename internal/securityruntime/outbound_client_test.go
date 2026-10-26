package securityruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReusableOutboundClientPreservesTrustAndLivePolicy(t *testing.T) {
	for _, scenario := range []string{"untrusted TLS", "policy tightened", "disallowed redirect", "scheme tightened"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv(envOutboundAllowLoopback, "true")
			t.Setenv(envOutboundAllowlistMode, "true")
			t.Setenv(envOutboundAllowedHosts, "127.0.0.1")
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "https://localhost/blocked", http.StatusTemporaryRedirect)
					return
				}
				_, _ = w.Write([]byte("accepted"))
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			if scenario != "untrusted TLS" {
				roots.AddCert(server.Certificate())
			}
			client := NewReusableOutboundHTTPClient(&http.Client{
				Timeout:   time.Second,
				Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
			}, "https")
			defer client.CloseIdleConnections()
			request := func(endpoint string) error {
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
				if err != nil {
					return err
				}
				resp, err := DoOutboundRequest(client, req)
				if resp != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				return err
			}
			err := request(server.URL)
			if scenario == "untrusted TLS" {
				if err == nil || requests.Load() != 0 {
					t.Fatalf("untrusted request: err=%v requests=%d", err, requests.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			endpoint, wantRequests := server.URL, int32(1)
			switch scenario {
			case "policy tightened":
				t.Setenv(envOutboundAllowLoopback, "false")
			case "disallowed redirect":
				endpoint += "/redirect"
				wantRequests = 2
			case "scheme tightened":
				endpoint = strings.Replace(server.URL, "https:", "http:", 1)
			}
			if err := request(endpoint); err == nil {
				t.Fatal("expected current outbound policy to reject request")
			}
			if got := requests.Load(); got != wantRequests {
				t.Fatalf("requests=%d, want %d", got, wantRequests)
			}
		})
	}
}
