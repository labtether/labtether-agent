package docker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real TLS chain with a distinct root proves that the bridge exports the
// verified terminal certificate, rather than trusting the server's leaf.
func composeTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Compose test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Compose test server"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = nil
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, rootDER
}

func composeTrustedClient(root []byte) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}))
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
}

type composeTLSChildRecord struct {
	Args              []string
	Env               map[string]string
	CA                string
	Root              []byte
	FileMode, DirMode uint32
}

// This re-exec uses the final command's CA/hostname/flags for one real TLS
// request. It is not Docker CLI; actual CLI acceptance remains a live check.
func TestComposeTLSChild(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "compose-tls-child" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	output, mode, args := os.Args[marker+1], os.Args[marker+2], os.Args[marker+3:]
	if len(args) < 8 || args[0] != "docker" || args[1] != "--host" || args[3] != "--tlsverify=true" || !strings.HasPrefix(args[4], "--tlscacert=") || args[5] != "--tlscert=" || args[6] != "--tlskey=" || args[7] != "compose" {
		os.Exit(21)
	}
	ca := strings.TrimPrefix(args[4], "--tlscacert=")
	data, err := os.ReadFile(ca)
	if err != nil {
		os.Exit(22)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		os.Exit(23)
	}
	fileInfo, err := os.Stat(ca)
	if err != nil {
		os.Exit(24)
	}
	dirInfo, err := os.Stat(filepath.Dir(ca))
	if err != nil {
		os.Exit(25)
	}
	record := composeTLSChildRecord{Args: args, CA: ca, Root: block.Bytes, Env: map[string]string{}, FileMode: uint32(fileInfo.Mode().Perm()), DirMode: uint32(dirInfo.Mode().Perm())}
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTPS_PROXY", "HOME", "DOCKER_CONFIG"} {
		record.Env[key] = os.Getenv(key)
	}
	client := composeTrustedClient(block.Bytes)
	response, err := client.Get("https://" + strings.TrimPrefix(args[2], "tcp://") + "/_ping")
	if err != nil {
		os.Exit(26)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		os.Exit(27)
	}
	data, _ = json.Marshal(record)
	if os.WriteFile(output, data, 0o600) != nil {
		os.Exit(28)
	}
	if mode == "wait" {
		time.Sleep(time.Minute)
		os.Exit(29)
	}
	_, _ = io.WriteString(os.Stdout, "verified compose ok")
	os.Exit(0)
}

func composeTLSChildHook(t *testing.T, output, mode string) **exec.Cmd {
	t.Helper()
	oldDetect, oldCommand := dockerComposeCLIDetect, dockerComposeNewCommandContext
	t.Cleanup(func() { dockerComposeCLIDetect, dockerComposeNewCommandContext = oldDetect, oldCommand })
	dockerComposeCLIDetect = func() (int, bool) { return 2, true }
	var child *exec.Cmd
	dockerComposeNewCommandContext = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		argv := []string{"-test.run=^TestComposeTLSChild$", "--", "compose-tls-child", output, mode, name}
		child = exec.CommandContext(ctx, os.Args[0], append(argv, args...)...)
		return child, nil
	}
	return &child
}

func readComposeTLSChild(t *testing.T, path string) composeTLSChildRecord {
	t.Helper()
	var record composeTLSChildRecord
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &record) != nil {
		t.Fatal("missing TLS child record", err)
	}
	return record
}

func assertComposeTrustRemoved(t *testing.T, ca string) {
	t.Helper()
	for _, path := range []string{ca, filepath.Dir(ca)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("owned trust path remains: %s (%v)", path, err)
		}
	}
}
