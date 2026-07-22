package agentcore

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labtether/labtether-agent/internal/servicehttp"
)

type Runtime struct {
	cfg       RuntimeConfig
	provider  TelemetryProvider
	publisher HeartbeatPublisher
	identity  *runtimeIdentitySource

	// WebSocket transport (nil when using HTTP-only mode).
	transport      *wsTransport
	telemetryBuf   *RingBuffer[TelemetrySample]
	deviceIdentity *deviceIdentity

	// HeartbeatCounter is incremented on every heartbeat tick; monitored by the watchdog.
	HeartbeatCounter atomic.Int64

	// Dynamic config overrides (0 = use default from cfg).
	collectIntervalOverride   atomic.Int64
	heartbeatIntervalOverride atomic.Int64
	baseCollectInterval       time.Duration
	baseHeartbeatInterval     time.Duration

	startedAt time.Time
	alerts    []AlertSnapshot

	mu               sync.RWMutex
	sample           TelemetrySample
	lastCollectErr   string
	lastCollectErrAt time.Time
	lastPublishErr   string
	lastPublishErrAt time.Time
	localBindAddress string
	localAuthEnabled bool
}

func NewRuntime(cfg RuntimeConfig, provider TelemetryProvider, publisher HeartbeatPublisher) *Runtime {
	return newRuntimeWithIdentity(cfg, provider, publisher, newRuntimeIdentitySource(cfg))
}

func newRuntimeWithIdentity(cfg RuntimeConfig, provider TelemetryProvider, publisher HeartbeatPublisher, identity *runtimeIdentitySource) *Runtime {
	now := time.Now().UTC()
	if identity == nil {
		identity = newRuntimeIdentitySource(cfg)
	}
	cfg.APIToken = ""
	return &Runtime{
		cfg:                   cfg,
		provider:              provider,
		publisher:             publisher,
		identity:              identity,
		baseCollectInterval:   cfg.CollectInterval,
		baseHeartbeatInterval: cfg.HeartbeatInterval,
		startedAt:             now,
		sample: TelemetrySample{
			AssetID:     cfg.AssetID,
			CollectedAt: now,
		},
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	bindAddress := resolveAgentLocalBindAddress()
	localAuthConfig := r.cfg
	localAuthConfig.APIToken = r.identity.Snapshot().BearerToken
	localAuth, err := resolveAgentLocalAuth(localAuthConfig, bindAddress)
	localAuthConfig.APIToken = ""
	if err != nil {
		return err
	}
	r.localBindAddress = bindAddress
	r.localAuthEnabled = strings.TrimSpace(localAuth.token) != "" || localAuth.useRuntimeIdentity

	go r.collectLoop(ctx)
	go r.heartbeatLoop(ctx)

	serviceConfig := servicehttp.Config{
		Name:        r.cfg.Name,
		Port:        r.cfg.Port,
		BindAddress: bindAddress,
		AuthToken:   localAuth.token,
		ExtraHandlers: map[string]http.HandlerFunc{
			"/agent/info": func(w http.ResponseWriter, req *http.Request) {
				servicehttp.WriteJSON(w, http.StatusOK, r.provider.AgentInfo())
			},
			"/agent/telemetry": func(w http.ResponseWriter, req *http.Request) {
				servicehttp.WriteJSON(w, http.StatusOK, r.current())
			},
			"/agent/status": r.statusHandler(),
			"/metrics": func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
				_, _ = w.Write([]byte(RenderPrometheus(r.current())))
			},
		},
	}
	if localAuth.useRuntimeIdentity {
		serviceConfig.AuthToken = ""
		serviceConfig.AuthTokenProvider = func() string {
			return r.identity.Snapshot().BearerToken
		}
	}
	return servicehttp.Run(ctx, serviceConfig)
}

const (
	envAgentLocalBindAddress       = "LABTETHER_AGENT_LOCAL_BIND_ADDRESS"
	envAgentLocalAuthToken         = "LABTETHER_AGENT_LOCAL_AUTH_TOKEN"      // #nosec G101 -- environment variable key name, not an embedded credential.
	envAgentLocalAuthTokenFile     = "LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE" // #nosec G101 -- environment variable key name, not an embedded credential.
	envAgentLocalAllowUnauth       = "LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED"
	defaultAgentLocalBindAddress   = "127.0.0.1"
	defaultAgentLocalBindAddressV6 = "::1"
)

func resolveAgentLocalBindAddress() string {
	bindAddress := strings.TrimSpace(os.Getenv(envAgentLocalBindAddress))
	if bindAddress == "" {
		return defaultAgentLocalBindAddress
	}
	return bindAddress
}

type agentLocalAuthResolution struct {
	token              string
	useRuntimeIdentity bool
}

func resolveAgentLocalAuthToken(cfg RuntimeConfig, bindAddress string) (string, error) {
	resolution, err := resolveAgentLocalAuth(cfg, bindAddress)
	return resolution.token, err
}

func resolveAgentLocalAuth(cfg RuntimeConfig, bindAddress string) (agentLocalAuthResolution, error) {
	if token := strings.TrimSpace(os.Getenv(envAgentLocalAuthToken)); token != "" {
		return agentLocalAuthResolution{token: token}, nil
	}
	if tokenPath := strings.TrimSpace(os.Getenv(envAgentLocalAuthTokenFile)); tokenPath != "" {
		token, err := loadSecretFromFile(tokenPath)
		if err != nil {
			return agentLocalAuthResolution{}, fmt.Errorf("failed to load %s: %w", envAgentLocalAuthTokenFile, err)
		}
		if token = strings.TrimSpace(token); token != "" {
			return agentLocalAuthResolution{token: token}, nil
		}
	}
	if isLoopbackBindAddress(bindAddress) {
		return agentLocalAuthResolution{}, nil
	}
	if parseBoolEnv(envAgentLocalAllowUnauth, false) {
		log.Printf("%s: WARNING: non-loopback local API binding is unauthenticated (%s=true)", cfg.Name, envAgentLocalAllowUnauth)
		return agentLocalAuthResolution{}, nil
	}
	if token := strings.TrimSpace(cfg.APIToken); token != "" {
		return agentLocalAuthResolution{token: token, useRuntimeIdentity: true}, nil
	}
	return agentLocalAuthResolution{}, fmt.Errorf("non-loopback local API binding requires %s or %s=true", envAgentLocalAuthToken, envAgentLocalAllowUnauth)
}

func isLoopbackBindAddress(value string) bool {
	normalized := strings.TrimSpace(strings.ToLower(value))
	switch normalized {
	case "", "localhost", defaultAgentLocalBindAddress, defaultAgentLocalBindAddressV6:
		return true
	}
	if ip := net.ParseIP(normalized); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (r *Runtime) collectLoop(ctx context.Context) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("agent: panic in collectLoop: %v\n%s", err, debug.Stack())
		}
	}()
	r.collectOnce(time.Now().UTC())
	currentInterval := r.cfg.CollectInterval
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("%s telemetry collector stopped", r.cfg.Name)
			return
		case tick := <-ticker.C:
			r.collectOnce(tick.UTC())
			// Check for dynamic interval override.
			if override := r.collectIntervalOverride.Load(); override > 0 {
				newInterval := time.Duration(override) * time.Second
				if newInterval != currentInterval {
					currentInterval = newInterval
					ticker.Reset(currentInterval)
					log.Printf("%s: collect interval updated to %v", r.cfg.Name, currentInterval)
				}
			}
		}
	}
}

func (r *Runtime) heartbeatLoop(ctx context.Context) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("agent: panic in heartbeatLoop: %v\n%s", err, debug.Stack())
		}
	}()
	r.publishOnce(ctx)
	currentInterval := r.cfg.HeartbeatInterval
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("%s heartbeat loop stopped", r.cfg.Name)
			return
		case <-ticker.C:
			r.publishOnce(ctx)
			r.HeartbeatCounter.Add(1)
			// Check for dynamic interval override.
			if override := r.heartbeatIntervalOverride.Load(); override > 0 {
				newInterval := time.Duration(override) * time.Second
				if newInterval != currentInterval {
					currentInterval = newInterval
					ticker.Reset(currentInterval)
					log.Printf("%s: heartbeat interval updated to %v", r.cfg.Name, currentInterval)
				}
			}
		}
	}
}

func (r *Runtime) collectOnce(now time.Time) {
	sample, err := r.provider.Collect(now)
	if err != nil {
		r.logCollectWarning(err)
	}
	if assetID := r.identity.AssetID(); assetID != "" {
		sample.AssetID = assetID
	} else if sample.AssetID == "" {
		sample.AssetID = r.cfg.AssetID
	}
	if sample.CollectedAt.IsZero() {
		sample.CollectedAt = now
	}
	sample.CPUPercent = ClampPercent(sample.CPUPercent)
	sample.MemoryPercent = ClampPercent(sample.MemoryPercent)
	sample.DiskPercent = ClampPercent(sample.DiskPercent)

	r.mu.Lock()
	r.sample = sample
	r.mu.Unlock()
}

func (r *Runtime) publishOnce(ctx context.Context) {
	sample := r.current()
	if err := r.publisher.Publish(ctx, sample); err != nil {
		r.logPublishWarning(err)
	}

	// Also send a dedicated telemetry message over WebSocket.
	if r.transport != nil {
		if r.transport.Connected() {
			sendTelemetrySample(r.transport, sample)
		} else if r.telemetryBuf != nil {
			r.telemetryBuf.Push(sample)
		}
	}
}

func (r *Runtime) current() TelemetrySample {
	r.mu.RLock()
	sample := r.sample
	r.mu.RUnlock()
	if assetID := r.identity.AssetID(); assetID != "" {
		sample.AssetID = assetID
	}
	return sample
}

func (r *Runtime) logCollectWarning(err error) {
	r.logWarning("collect", err, &r.lastCollectErr, &r.lastCollectErrAt)
}

func (r *Runtime) logPublishWarning(err error) {
	r.logWarning("heartbeat", err, &r.lastPublishErr, &r.lastPublishErrAt)
}

func (r *Runtime) logWarning(scope string, err error, lastMessage *string, lastAt *time.Time) {
	if err == nil {
		return
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		message = "unknown error"
	}
	now := time.Now().UTC()

	r.mu.Lock()
	if message == *lastMessage && now.Sub(*lastAt) < 5*time.Minute {
		r.mu.Unlock()
		return
	}
	*lastMessage = message
	*lastAt = now
	r.mu.Unlock()

	log.Printf("%s %s warning: %s", r.cfg.Name, scope, message)
}
