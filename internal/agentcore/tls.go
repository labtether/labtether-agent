package agentcore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

var loadSystemCertPool = x509.SystemCertPool

// buildTLSConfig creates a *tls.Config from agent TLS settings.
// Returns nil when no TLS options are configured (plain HTTP mode).
func buildTLSConfig(cfg *RuntimeConfig) *tls.Config {
	if cfg == nil {
		return nil
	}
	caFile := strings.TrimSpace(cfg.TLSCAFile)
	if caFile == "" && !cfg.TLSSkipVerify {
		return nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// A configured CA wins over a stale skip-verify setting from a wrapper.
		// #nosec G402 -- operator opt-in for local/dev without a configured CA.
		InsecureSkipVerify: cfg.TLSSkipVerify && caFile == "", //nolint:gosec // #nosec G402 -- operator opt-in for dev/self-signed
	}

	if caFile != "" {
		caCert, err := readBoundedRegularFile(caFile, maxLocalCAFileBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: warning: failed to read TLS CA file %s: %v\n", caFile, err)
			return tlsCfg
		}
		pool, err := loadSystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			fmt.Fprintf(os.Stderr, "agent: warning: no valid certs found in %s\n", caFile)
			return tlsCfg
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg
}
