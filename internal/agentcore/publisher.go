package agentcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/labtether/labtether-agent/internal/assets"
	"github.com/labtether/labtether-agent/internal/platforms"
	"github.com/labtether/labtether-agent/internal/securityruntime"
)

func NewHeartbeatPublisher(cfg RuntimeConfig, staticMetadata map[string]string) HeartbeatPublisher {
	return newHeartbeatPublisherWithRuntimeIdentity(cfg, staticMetadata, newRuntimeIdentitySource(cfg))
}

func newHeartbeatPublisherWithRuntimeIdentity(cfg RuntimeConfig, staticMetadata map[string]string, identity *runtimeIdentitySource) HeartbeatPublisher {
	scheme := "https"
	if endpoint, err := url.Parse(cfg.APIBaseURL); err == nil && endpoint.Scheme != "" {
		scheme = endpoint.Scheme
	}

	return &apiHeartbeatPublisher{
		client:   heartbeatHTTPClient(buildTLSConfig(&cfg), scheme),
		scheme:   scheme,
		source:   cfg.Source,
		meta:     cloneStringMap(staticMetadata),
		identity: identity,
	}
}

func heartbeatHTTPClient(tlsCfg *tls.Config, scheme string) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
	}
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	return securityruntime.NewReusableOutboundHTTPClient(&http.Client{
		Timeout:   6 * time.Second,
		Transport: transport,
	}, scheme)
}

type apiHeartbeatPublisher struct {
	mu       sync.Mutex
	client   *http.Client // replaced by useHubTLSConfig
	scheme   string
	source   string
	meta     map[string]string
	identity *runtimeIdentitySource
}

// useHubTLSConfig makes the next heartbeat connect with tlsCfg, after a late
// enrollment saved the Hub's CA.
func (p *apiHeartbeatPublisher) useHubTLSConfig(tlsCfg *tls.Config) {
	next := heartbeatHTTPClient(tlsCfg, p.scheme)
	p.mu.Lock()
	previous := p.client
	p.client = next
	p.mu.Unlock()
	previous.CloseIdleConnections()
}

var errHeartbeatCredentialsUnavailable = errors.New("heartbeat credentials are not available")

func (p *apiHeartbeatPublisher) Publish(ctx context.Context, sample TelemetrySample) error {
	identity := p.identity.Snapshot()
	if identity.APIBaseURL == "" || identity.BearerToken == "" || identity.AssetID == "" {
		return errHeartbeatCredentialsUnavailable
	}
	metadata := heartbeatMetadata(p.meta, sample)
	resolvedPlatform := resolveHeartbeatPlatform(metadata)
	if resolvedPlatform != "" {
		metadata["platform"] = resolvedPlatform
	}

	payload := assets.HeartbeatRequest{
		AssetID:  identity.AssetID,
		Type:     "host",
		Name:     identity.AssetID,
		Source:   p.source,
		GroupID:  identity.GroupID,
		Status:   "online",
		Platform: resolvedPlatform,
		Metadata: metadata,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	endpoint := strings.TrimRight(identity.APIBaseURL, "/") + "/assets/heartbeat"
	req, err := securityruntime.NewOutboundRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+identity.BearerToken)

	p.mu.Lock()
	client := p.client
	p.mu.Unlock()
	resp, err := securityruntime.DoOutboundRequest(client, req)
	if err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	defer resp.Body.Close()
	// Read normal small acknowledgements so Go 1.26 can reuse the connection.
	// A large or stalled response remains bounded by this cap and client timeout.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat rejected with status %d", resp.StatusCode)
	}
	return nil
}

type noopHeartbeatPublisher struct{}

func (noopHeartbeatPublisher) Publish(context.Context, TelemetrySample) error {
	return nil
}

func cloneStringMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func resolveHeartbeatPlatform(metadata map[string]string) string {
	return platforms.Resolve(
		metadata["platform"],
		metadata["os"],
		metadata["os_name"],
		metadata["os_pretty_name"],
	)
}
