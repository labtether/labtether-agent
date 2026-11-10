package agentcore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// envTLSCAOnly makes the CA file the only trusted root for connections to the
// Hub. Without it the agent trusts the system roots plus the CA file, so a
// server holding any publicly trusted certificate for the Hub's host name
// could pass as the Hub and receive the agent token. It is read from the
// environment only: a Hub cannot turn it off.
const envTLSCAOnly = "LABTETHER_TLS_CA_ONLY"

// parseTLSCAOnlyEnv reads the option. A value that is not a boolean counts as
// on, so a typo never falls back to the system roots; validateTLSCAOnly then
// stops the agent at start with the reason.
func parseTLSCAOnlyEnv() bool {
	raw := strings.TrimSpace(os.Getenv(envTLSCAOnly))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err != nil || enabled
}

// validateTLSCAOnly is the start check: with the option on, the agent runs
// only when the CA file is set and holds a certificate.
func validateTLSCAOnly(cfg RuntimeConfig) error {
	if raw := strings.TrimSpace(os.Getenv(envTLSCAOnly)); raw != "" {
		if _, err := strconv.ParseBool(raw); err != nil {
			return fmt.Errorf("%s must be true or false, not %q", envTLSCAOnly, raw)
		}
	}
	if !cfg.TLSCAOnly {
		return nil
	}
	_, err := loadCAOnlyPool(cfg.TLSCAFile)
	return err
}

func loadCAOnlyPool(caFile string) (*x509.CertPool, error) {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return nil, errors.New(envTLSCAOnly + " is on but no CA file is set: set LABTETHER_TLS_CA_FILE to the Hub's CA certificate, or turn " + envTLSCAOnly + " off")
	}
	raw, err := readBoundedRegularFile(caFile, maxLocalCAFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%s is on but the CA file %s cannot be read: %w", envTLSCAOnly, caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s is on but the CA file %s holds no certificate", envTLSCAOnly, caFile)
	}
	return pool, nil
}

// hubCAOnlyTLSConfig trusts only the configured CA file and never skips
// verification. If the file cannot be used the pool stays empty, so the
// connection is refused instead of falling back to the system roots.
func hubCAOnlyTLSConfig(cfg *RuntimeConfig) *tls.Config {
	pool, err := loadCAOnlyPool(cfg.TLSCAFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		pool = x509.NewCertPool()
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
}

// hubHostnames lists the host names of the Hub's API and WebSocket addresses.
func hubHostnames(cfg RuntimeConfig) map[string]struct{} {
	hosts := make(map[string]struct{}, 2)
	for _, raw := range []string{cfg.APIBaseURL, cfg.WSBaseURL} {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if host := normalizeTLSHostname(parsed.Hostname()); host != "" {
			hosts[host] = struct{}{}
		}
	}
	return hosts
}

func normalizeTLSHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// newSelfUpdateTransport is the transport for update checks and downloads.
// They are the only requests that may leave the Hub (a custom update source,
// a release host, a redirect). With the CA-only option on, a request to the
// Hub's host name trusts only the CA file; any other host keeps the system
// roots, as before.
func newSelfUpdateTransport(cfg RuntimeConfig) http.RoundTripper {
	other := &http.Transport{}
	if tlsCfg := systemRootsTLSConfig(&cfg); tlsCfg != nil {
		other.TLSClientConfig = tlsCfg
	}
	if !cfg.TLSCAOnly {
		return other
	}
	hubHosts := hubHostnames(cfg)
	return &securityruntime.HostRoutedTransport{
		Match: func(hostname string) bool {
			_, isHub := hubHosts[normalizeTLSHostname(hostname)]
			return isHub
		},
		Matched: &http.Transport{TLSClientConfig: hubCAOnlyTLSConfig(&cfg)},
		Other:   other,
	}
}
