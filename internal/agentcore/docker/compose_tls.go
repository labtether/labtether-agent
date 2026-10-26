package docker

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const composeTLSProbeTimeout = 5 * time.Second

// Only public trust anchors are exported. No Hub trust or ambient Docker client
// credentials enter this bridge. The CLI still verifies the original hostname.
func (dc *DockerCollector) prepareComposeTLS(ctx context.Context) (*composeTLSMaterial, error) {
	ctx, cancel := context.WithTimeout(ctx, composeTLSProbeTimeout)
	defer cancel()
	if dc.client == nil || dc.client.httpClient == nil || dc.client.baseURL != strings.TrimRight(strings.TrimSpace(dc.socketPath), "/") {
		return nil, fmt.Errorf("HTTPS Compose collector endpoint is unavailable")
	}
	req, err := dc.client.newRequest(ctx, http.MethodGet, dc.client.baseURL+"/_ping", nil)
	if err != nil {
		return nil, err
	}
	base := dc.client.httpClient
	transport, ok := base.Transport.(*http.Transport)
	if base.Transport == nil {
		transport, ok = http.DefaultTransport.(*http.Transport)
	}
	if !ok || transport == nil {
		return nil, fmt.Errorf("HTTPS Compose requires a verified HTTP transport")
	}
	transport = transport.Clone()
	// Require a fresh handshake and bound headers, body and elapsed time. The
	// collector's outbound owner retains its URL and per-dial network policy.
	transport.DisableKeepAlives = true
	transport.TLSHandshakeTimeout = composeTLSProbeTimeout
	transport.ResponseHeaderTimeout = composeTLSProbeTimeout
	transport.MaxResponseHeaderBytes = 16 * 1024
	client := *base
	client.Transport = transport
	client.Timeout = composeTLSProbeTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := dc.client.doRequest(&client, req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("HTTPS Compose could not verify the collector TLS connection")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 {
		return nil, fmt.Errorf("HTTPS Compose requires a verified, non-redirected Docker response")
	}
	if size, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4097)); err != nil || size > 4096 {
		return nil, fmt.Errorf("HTTPS Compose verification response exceeded its limit or failed")
	}
	var certificates []byte
	seen := make(map[[32]byte]bool)
	if len(response.TLS.VerifiedChains) > 16 {
		return nil, fmt.Errorf("HTTPS Compose verified chain count exceeded its limit")
	}
	for _, chain := range response.TLS.VerifiedChains {
		if len(chain) == 0 || chain[0].VerifyHostname(req.URL.Hostname()) != nil {
			return nil, fmt.Errorf("HTTPS Compose requires the collector's original verified hostname")
		}
		root := chain[len(chain)-1]
		if len(root.Raw) > 48*1024 {
			return nil, fmt.Errorf("HTTPS Compose verified root exceeded its limit")
		}
		digest := sha256.Sum256(root.Raw)
		if !seen[digest] {
			certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
			seen[digest] = true
		}
		if len(certificates) > 64*1024 {
			return nil, fmt.Errorf("HTTPS Compose verified trust roots exceeded their limit")
		}
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("HTTPS Compose has no verified trust roots")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return newComposeTLSMaterial(certificates)
}

type composeTLSMaterial struct {
	dir, file         string
	dirInfo, fileInfo os.FileInfo
	fileGone, dirGone bool
}

func newComposeTLSMaterial(certificates []byte) (material *composeTLSMaterial, err error) {
	dir, err := os.MkdirTemp("", "labtether-compose-ca-")
	if err != nil {
		return nil, fmt.Errorf("could not create private Compose TLS trust directory")
	}
	owned := &composeTLSMaterial{dir: dir, file: filepath.Join(dir, "ca.pem")}
	owned.dirInfo, err = os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("could not capture Compose TLS trust directory")
	}
	defer func() {
		if err != nil && owned.close() != nil {
			err = fmt.Errorf("Compose TLS trust setup and cleanup failed")
		}
	}()
	file, err := os.OpenFile(owned.file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- fixed name in a fresh private MkdirTemp directory.
	if err != nil {
		owned.fileGone = true
		return nil, fmt.Errorf("could not create Compose TLS trust file")
	}
	owned.fileInfo, err = file.Stat()
	if err == nil {
		_, err = file.Write(certificates)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, fmt.Errorf("could not write Compose TLS trust file")
	}
	return owned, nil
}

func (material *composeTLSMaterial) flags() []string {
	return []string{"--tlsverify=true", "--tlscacert=" + material.file, "--tlscert=", "--tlskey="}
}

// Never recursively remove this directory or delete a replacement object.
func (material *composeTLSMaterial) close() error {
	if material.dirGone {
		return nil
	}
	info, err := os.Lstat(material.dir)
	if err != nil || material.dirInfo == nil || !os.SameFile(info, material.dirInfo) || !info.IsDir() {
		return fmt.Errorf("Compose TLS trust directory identity changed")
	}
	if !material.fileGone {
		info, err = os.Lstat(material.file)
		if err != nil || material.fileInfo == nil || !os.SameFile(info, material.fileInfo) || !info.Mode().IsRegular() {
			return fmt.Errorf("Compose TLS trust file identity changed")
		}
		if err := os.Remove(material.file); err != nil {
			return err
		}
		material.fileGone = true
	}
	if err := os.Remove(material.dir); err != nil {
		return err
	}
	material.dirGone = true
	return nil
}
