package agentcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/assets"
	"github.com/labtether/labtether-agent/internal/metricschema"
	"github.com/labtether/labtether-agent/internal/platforms"
	"github.com/labtether/labtether-agent/internal/securityruntime"
)

func NewHeartbeatPublisher(cfg RuntimeConfig, staticMetadata map[string]string) HeartbeatPublisher {
	return newHeartbeatPublisherWithRuntimeIdentity(cfg, staticMetadata, newRuntimeIdentitySource(cfg))
}

func newHeartbeatPublisherWithRuntimeIdentity(cfg RuntimeConfig, staticMetadata map[string]string, identity *runtimeIdentitySource) HeartbeatPublisher {
	transport := &http.Transport{}
	if tlsCfg := buildTLSConfig(&cfg); tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}

	return &apiHeartbeatPublisher{
		client: &http.Client{
			Timeout:   6 * time.Second,
			Transport: transport,
		},
		source:   cfg.Source,
		groupID:  cfg.GroupID,
		meta:     cloneStringMap(staticMetadata),
		identity: identity,
	}
}

type apiHeartbeatPublisher struct {
	client   *http.Client
	source   string
	groupID  string
	meta     map[string]string
	identity *runtimeIdentitySource
}

var errHeartbeatCredentialsUnavailable = errors.New("heartbeat credentials are not available")

func (p *apiHeartbeatPublisher) Publish(ctx context.Context, sample TelemetrySample) error {
	identity := p.identity.Snapshot()
	if identity.APIBaseURL == "" || identity.BearerToken == "" || identity.AssetID == "" {
		return errHeartbeatCredentialsUnavailable
	}
	metadata := cloneStringMap(p.meta)
	metadata[metricschema.HeartbeatKeyCPUPercent] = fmt.Sprintf("%.2f", sample.CPUPercent)
	metadata[metricschema.HeartbeatKeyCPUUsedPercent] = fmt.Sprintf("%.2f", sample.CPUPercent)
	metadata[metricschema.HeartbeatKeyMemoryPercent] = fmt.Sprintf("%.2f", sample.MemoryPercent)
	metadata[metricschema.HeartbeatKeyMemoryUsedPercent] = fmt.Sprintf("%.2f", sample.MemoryPercent)
	metadata[metricschema.HeartbeatKeyDiskPercent] = fmt.Sprintf("%.2f", sample.DiskPercent)
	metadata[metricschema.HeartbeatKeyDiskUsedPercent] = fmt.Sprintf("%.2f", sample.DiskPercent)
	metadata[metricschema.HeartbeatKeyNetworkRXBytesPerSec] = fmt.Sprintf("%.2f", sample.NetRXBytesPerSec)
	metadata[metricschema.HeartbeatKeyNetworkTXBytesPerSec] = fmt.Sprintf("%.2f", sample.NetTXBytesPerSec)
	if sample.TempCelsius != nil {
		metadata[metricschema.HeartbeatKeyTempCelsius] = fmt.Sprintf("%.2f", *sample.TempCelsius)
		metadata[metricschema.HeartbeatKeyTemperatureCelsius] = fmt.Sprintf("%.2f", *sample.TempCelsius)
	}
	resolvedPlatform := resolveHeartbeatPlatform(metadata)
	if resolvedPlatform != "" {
		metadata["platform"] = resolvedPlatform
	}

	payload := assets.HeartbeatRequest{
		AssetID:  identity.AssetID,
		Type:     "host",
		Name:     identity.AssetID,
		Source:   p.source,
		GroupID:  p.groupID,
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

	resp, err := securityruntime.DoOutboundRequest(p.client, req)
	if err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	defer resp.Body.Close()

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
