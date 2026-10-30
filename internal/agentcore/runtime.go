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
	// heartbeatTickInterval is the interval the heartbeat ticker currently
	// uses, in nanoseconds. The watchdog scales its stuck threshold from it.
	heartbeatTickInterval atomic.Int64

	// Dynamic config overrides (0 = use default from cfg).
	collectIntervalOverride   atomic.Int64
	heartbeatIntervalOverride atomic.Int64
	baseCollectInterval       time.Duration
	baseHeartbeatInterval     time.Duration

	startedAt time.Time
	alerts    []AlertSnapshot

	// firstSample closes once the first collection has stored real values.
	firstSample     chan struct{}
	firstSampleOnce sync.Once

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
			pending:     true,
		},
		firstSample: make(chan struct{}),
	}
}

// Run starts telemetry collection and heartbeats, then serves the optional
// local API until ctx ends. A local API problem is logged and never stops the
// agent: the Hub connection, terminal and updates keep working without it.
func (r *Runtime) Run(ctx context.Context) error {
	bindAddress := resolveAgentLocalBindAddress()
	r.localBindAddress = bindAddress
	localAuth, authErr := resolveAgentLocalAuth(r.cfg, bindAddress)
	r.localAuthEnabled = authErr == nil && strings.TrimSpace(localAuth.token) != ""

	go r.collectLoop(ctx)
	go r.heartbeatLoop(ctx)

	if authErr != nil {
		log.Printf("%s: local API is off: %v", r.cfg.Name, authErr)
		<-ctx.Done()
		return nil
	}

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
	serveLocalAPI(ctx, serviceConfig)
	return nil
}

const (
	localAPIRetryInitialDelay = 30 * time.Second
	localAPIRetryMaxDelay     = 5 * time.Minute
)

// serveLocalAPI keeps retrying the local API listener until ctx ends. Another
// program (or any local user) holding the port must not take the agent down,
// so a failed bind is logged and retried with a growing delay.
func serveLocalAPI(ctx context.Context, cfg servicehttp.Config) {
	delay := localAPIRetryInitialDelay
	for {
		err := servicehttp.Run(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("listener stopped")
		}
		log.Printf("%s: local API unavailable on %s: %v; retrying in %s. The Hub connection is not affected.",
			cfg.Name, net.JoinHostPort(cfg.BindAddress, cfg.Port), err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, localAPIRetryMaxDelay)
	}
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
	token string
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
	currentInterval := r.cfg.HeartbeatInterval
	r.heartbeatTickInterval.Store(int64(currentInterval))
	if !r.waitForFirstSample(ctx, firstSampleWait) {
		return
	}
	r.publishOnce(ctx)
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
					r.heartbeatTickInterval.Store(int64(currentInterval))
					log.Printf("%s: heartbeat interval updated to %v", r.cfg.Name, currentInterval)
				}
			}
		}
	}
}

// watchdogHeartbeatInterval reports the heartbeat ticker's current interval,
// falling back to the configured value before the loop has started.
func (r *Runtime) watchdogHeartbeatInterval() time.Duration {
	if ticking := r.heartbeatTickInterval.Load(); ticking > 0 {
		return time.Duration(ticking)
	}
	return time.Duration(r.effectiveHeartbeatIntervalSec()) * time.Second
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
	if r.firstSample != nil {
		r.firstSampleOnce.Do(func() { close(r.firstSample) })
	}
}

// firstSampleWait bounds how long the first heartbeat waits for the first
// collection. Windows and macOS collection can take a few seconds at start.
const firstSampleWait = 15 * time.Second

// waitForFirstSample holds the first heartbeat until real values exist, so
// the Hub never records the zeroed placeholder. It returns false when ctx ends.
func (r *Runtime) waitForFirstSample(ctx context.Context, limit time.Duration) bool {
	if r.firstSample == nil {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-r.firstSample:
	case <-timer.C:
		log.Printf("%s: first telemetry collection is still running; sending the heartbeat without metrics", r.cfg.Name)
	case <-ctx.Done():
		return false
	}
	return true
}

func (r *Runtime) publishOnce(ctx context.Context) {
	sample := r.current()
	heartbeatSample := sample
	if provider, ok := r.provider.(HeartbeatMetadataProvider); ok {
		heartbeatSample.heartbeatMetadata = provider.HeartbeatMetadata()
	}
	if err := r.publisher.Publish(ctx, heartbeatSample); err != nil {
		r.logPublishWarning(err)
	} else {
		// A heartbeat reached the Hub: a freshly installed update is healthy.
		confirmSelfUpdateHealthy()
	}

	// Live samples join the replay queue first so they cannot overtake its
	// retained tail or disappear in a Connected-to-Send race.
	if r.transport != nil && r.telemetryBuf != nil && !sample.pending {
		r.telemetryBuf.Push(sample)
		_ = replayBufferedTelemetry(r.transport, r.telemetryBuf)
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
