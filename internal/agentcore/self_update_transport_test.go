package agentcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSelfUpdateTokenAudience(t *testing.T) {
	cfg := RuntimeConfig{APIBaseURL: "https://hub.example.test", AutoUpdateCheckURL: "https://mirror.example.test/latest"}
	for _, endpoint := range []string{
		"https://mirror.example.test/latest", "https://mirror.example.test/binary",
		"https://child.hub.example.test/binary", "http://hub.example.test/binary",
		"https://hub.example.test:444/binary",
	} {
		if shouldAttachUpdateToken(cfg, endpoint) {
			t.Errorf("Hub token authorized for %s", endpoint)
		}
	}
	if !shouldAttachUpdateToken(cfg, "https://hub.example.test/binary") {
		t.Fatal("canonical Hub token was withheld")
	}
	cfg.APIBaseURL = ""
	cfg.WSBaseURL = "wss://hub.example.test/ws/agent"
	if !shouldAttachUpdateToken(cfg, "https://hub.example.test/binary") {
		t.Fatal("WebSocket Hub origin was not recognized")
	}
	cfg.WSBaseURL = ""
	if shouldAttachUpdateToken(cfg, "https://mirror.example.test/binary") {
		t.Fatal("custom mirror became a credential audience without a Hub")
	}
}

func TestSelfUpdateTLSMetadataAndBinaryAudience(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "false")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSelfUpdateTrustedPublicKey, base64.StdEncoding.EncodeToString(publicKey))
	binary := []byte("local signed update fixture")
	for _, canonical := range []bool{false, true} {
		name := "external mirror"
		if canonical {
			name = "canonical Hub"
		}
		t.Run(name, func(t *testing.T) {
			received := make(chan string, 2)
			var release agentReleaseMetadata
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				received <- req.Header.Get("Authorization")
				if req.URL.Path == "/release" {
					_ = json.NewEncoder(w).Encode(release)
					return
				}
				_, _ = w.Write(binary)
			}))
			defer server.Close()
			release = agentReleaseMetadata{Version: "v2.0.0", OS: runtime.GOOS, Arch: runtime.GOARCH,
				SHA256: sha256Hex(binary), URL: server.URL + "/binary", SizeBytes: int64(len(binary))}
			release.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(selfUpdateSignaturePayload(release))))
			cfg := selfUpdateTLSConfig(t, server)
			cfg.APIToken = "dummy-hub-token"
			cfg.APIBaseURL = "https://hub.example.invalid"
			cfg.AutoUpdateCheckURL = server.URL + "/release"
			expectedAuth := ""
			if canonical {
				cfg.APIBaseURL = server.URL
				expectedAuth = "Bearer dummy-hub-token"
			}
			fetched, err := fetchReleaseMetadata(cfg, buildAgentReleaseCheckURL(cfg))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateReleaseMetadata(cfg.AutoUpdateCheckURL, fetched.URL, fetched); err != nil {
				t.Fatal(err)
			}
			if err := verifyReleaseMetadataSignature(fetched, fetched.URL); err != nil {
				t.Fatal(err)
			}
			got, err := downloadReleaseBinary(cfg, fetched.URL, fetched.SizeBytes)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(binary) || sha256Hex(got) != fetched.SHA256 {
				t.Fatal("download changed")
			}
			for range 2 {
				if got := <-received; got != expectedAuth {
					t.Errorf("authorization = %q, want %q", got, expectedAuth)
				}
			}
		})
	}
}

func TestSelfUpdateTLSRedirectPolicy(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "false")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	for _, binary := range []bool{false, true} {
		for _, insecure := range []bool{false, true} {
			name := "metadata"
			if binary {
				name = "binary"
			}
			if insecure {
				name += " downgrade"
			} else {
				name += " cross origin"
			}
			t.Run(name, func(t *testing.T) {
				destinationAuth := make(chan string, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					destinationAuth <- req.Header.Get("Authorization")
					_, _ = w.Write([]byte(`{"version":"v2.0.0"}`))
				})
				var destination *httptest.Server
				if insecure {
					destination = httptest.NewServer(handler)
				} else {
					destination = httptest.NewTLSServer(handler)
				}
				defer destination.Close()
				originAuth := make(chan string, 1)
				origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					originAuth <- req.Header.Get("Authorization")
					http.Redirect(w, req, destination.URL, http.StatusFound)
				}))
				defer origin.Close()
				cfg := selfUpdateTLSConfig(t, origin)
				cfg.APIBaseURL = origin.URL
				cfg.APIToken = "dummy-hub-token"
				var err error
				if binary {
					_, err = downloadReleaseBinary(cfg, origin.URL, 0)
				} else {
					_, err = fetchReleaseMetadata(cfg, origin.URL)
				}
				if got := <-originAuth; got != "Bearer dummy-hub-token" {
					t.Fatalf("Hub auth = %q", got)
				}
				if insecure {
					if err == nil || !strings.Contains(err.Error(), "insecure") {
						t.Fatalf("downgrade error = %v", err)
					}
					select {
					case <-destinationAuth:
						t.Fatal("cleartext destination was contacted")
					default:
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if got := <-destinationAuth; got != "" {
						t.Fatalf("redirect leaked auth %q", got)
					}
				}
			})
		}
	}
}

func TestSelfUpdateRedirectStripsSubdomainToken(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "false")
	origin, _ := http.NewRequest(http.MethodGet, "https://hub.example.invalid/release", nil)
	destination, _ := http.NewRequest(http.MethodGet, "http://child.hub.example.invalid/binary", nil)
	destination.Header.Set("Authorization", "Bearer dummy-hub-token")
	_ = newSelfUpdateHTTPClient(RuntimeConfig{}).CheckRedirect(destination, []*http.Request{origin})
	if destination.Header.Get("Authorization") != "" {
		t.Fatal("subdomain redirect retained Hub token")
	}
}

func selfUpdateTLSConfig(t *testing.T, server *httptest.Server) RuntimeConfig {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "fixture-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return RuntimeConfig{TLSCAFile: caPath}
}
