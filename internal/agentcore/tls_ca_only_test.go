package agentcore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// The agent trusted the system roots plus the Hub's CA file. A server with
// any publicly trusted certificate for the Hub's host name therefore passed
// as the Hub and could receive the agent token. With LABTETHER_TLS_CA_ONLY
// on, only the CA file counts for the Hub. Other hosts, such as a release
// download, keep the system roots.
func TestTLSCAOnlyTrustsOnlyTheCAFileForTheHub(t *testing.T) {
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	hubCA := newTestAuthority(t, "Hub CA")
	publicRoot := newTestAuthority(t, "Public root")

	// The "system roots" hold the public root, as they hold real public CAs.
	systemRoots := x509.NewCertPool()
	systemRoots.AddCert(publicRoot.cert)
	savedLoad := loadSystemCertPool
	t.Cleanup(func() { loadSystemCertPool = savedLoad })
	loadSystemCertPool = func() (*x509.CertPool, error) { return systemRoots.Clone(), nil }

	caFile := filepath.Join(t.TempDir(), "hub-ca.crt")
	if err := os.WriteFile(caFile, hubCA.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	hub := hubCA.startServer(t)
	publiclyTrusted := publicRoot.startServer(t)

	hubOnly := func(cfg RuntimeConfig) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: buildTLSConfig(&cfg)}}
	}
	fetch := func(client *http.Client, target string) error {
		resp, err := client.Get(target)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}

	off := RuntimeConfig{TLSCAFile: caFile, APIBaseURL: hub.URL}
	on := off
	on.TLSCAOnly = true

	// Option off: the publicly trusted server passes. This is the gap, and
	// it shows the stubbed system roots are in use.
	if err := fetch(hubOnly(off), publiclyTrusted.URL); err != nil {
		t.Fatalf("test setup: without the option a publicly trusted server should pass: %v", err)
	}
	if err := fetch(hubOnly(on), hub.URL); err != nil {
		t.Fatalf("the Hub with its own CA was refused: %v", err)
	}
	if err := fetch(hubOnly(on), publiclyTrusted.URL); err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("a publicly trusted server passed as the Hub: %v", err)
	}

	// A CA file that cannot be used never falls back to the system roots,
	// and LABTETHER_TLS_SKIP_VERIFY does not open it up either.
	broken := on
	broken.TLSCAFile = filepath.Join(t.TempDir(), "missing.crt")
	broken.TLSSkipVerify = true
	if err := fetch(hubOnly(broken), publiclyTrusted.URL); err == nil {
		t.Fatal("with an unusable CA file the agent trusted a server anyway")
	}

	// Update checks and downloads: the Hub's host name trusts only the CA
	// file; another host (here "localhost", the Hub is 127.0.0.1) keeps the
	// system roots, so a release download from elsewhere still works.
	update := func(target string) error {
		req, err := securityruntime.NewOutboundRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		resp, err := securityruntime.DoOutboundRequest(newSelfUpdateHTTPClient(on), req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := update(hub.URL); err != nil {
		t.Fatalf("update check to the Hub was refused: %v", err)
	}
	if err := update(publiclyTrusted.URL); err == nil {
		t.Fatal("update check trusted a publicly trusted server on the Hub's host name")
	}
	elsewhere := strings.Replace(publiclyTrusted.URL, "127.0.0.1", "localhost", 1)
	if err := update(elsewhere); err != nil {
		t.Fatalf("a download from another host lost the system roots: %v", err)
	}
}

// With the option on and nothing to trust, the agent must stop at start and
// say what to set. A value that is not a boolean must not count as "off".
func TestTLSCAOnlyStopsTheAgentWithoutACAFile(t *testing.T) {
	err := Run(context.Background(), RuntimeConfig{Name: "labtether-agent", TLSCAOnly: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "LABTETHER_TLS_CA_ONLY is on but no CA file is set") ||
		!strings.Contains(err.Error(), "LABTETHER_TLS_CA_FILE") {
		t.Fatalf("start error: %v", err)
	}

	t.Setenv(envTLSCAOnly, "yes please")
	if !parseTLSCAOnlyEnv() {
		t.Fatal("a mistyped value turned the option off")
	}
	if err := validateTLSCAOnly(RuntimeConfig{TLSCAOnly: true}); err == nil || !strings.Contains(err.Error(), "must be true or false") {
		t.Fatalf("mistyped value: %v", err)
	}
}

type testAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{cert: cert, key: key}
}

func (a testAuthority) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
}

// startServer runs an HTTPS server on 127.0.0.1 whose certificate this
// authority signed, valid for 127.0.0.1, ::1 and localhost.
func (a testAuthority) startServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
