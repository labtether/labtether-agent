package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

func init() {
	// Wire the files subpackage's desktop session detector to root agentcore's
	// detectDesktopSession so that file path resolution can discover the active
	// desktop session without a circular import.
	files.DetectDesktopSessionFn = func() files.DesktopSessionInfo {
		session := detectDesktopSessionFn()
		return files.DesktopSessionInfo{
			Username: session.Username,
			UID:      session.UID,
		}
	}

	// Clipboard wiring is in init_clipboard_linux.go (build-tagged).
}

// Run wires the shared runtime with heartbeat publishing and starts HTTP endpoints.
// If LABTETHER_WS_URL is configured, it establishes a WebSocket transport to the
// hub and uses it for heartbeats, telemetry, and command execution. The HTTP
// heartbeat publisher is kept as fallback during WebSocket disconnects.
func Run(ctx context.Context, cfg RuntimeConfig, provider TelemetryProvider) error {
	setConnectorDiscoveryDockerConfig(cfg.DockerEnabled, cfg.DockerSocket)

	identity, identityErr := ensureDeviceIdentity(cfg)
	if identityErr != nil {
		log.Printf("%s: device identity initialization failed: %v", cfg.Name, identityErr)
	}

	if cfg.AutoUpdateEnabled {
		if err := maybeAutoUpdateOnStartup(cfg); err != nil {
			log.Printf("%s: auto-update check skipped: %v", cfg.Name, err)
		}
	}

	// Resolve API token: explicit env → persisted file → enrollment
	credentialWarning := ""
	credentialError := ""
	if err := resolveTokenWithIdentity(ctx, &cfg, identity); err != nil {
		log.Printf("%s: token resolution failed: %v", cfg.Name, err)
		if errors.Is(err, errAgentTokenPersistence) {
			credentialWarning = agentTokenPersistenceFailed
		}
		if isEnrollmentCredentialRejected(err) {
			credentialError = enrollmentTokenRejected
		}
	}

	if cfg.TLSSkipVerify {
		log.Printf("%s: WARNING: TLS certificate verification is disabled (LABTETHER_TLS_SKIP_VERIFY=true). This is insecure and should only be used for initial setup. Configure LABTETHER_TLS_CA_FILE to trust the hub CA.", cfg.Name)
	}

	staticMeta := provider.StaticMetadata()
	if staticMeta == nil {
		staticMeta = map[string]string{}
	}
	if version := strings.TrimSpace(cfg.Version); version != "" {
		staticMeta["agent_version"] = version
	}
	webrtcCaps := detectWebRTCCapabilitiesForConfig(cfg)
	capabilities := []string{"terminal", "desktop", "files"}
	if powerRuntime := newPlatformPowerBackend(); powerRuntime.Supported(powerActionReboot) && powerRuntime.Supported(powerActionShutdown) {
		capabilities = append(capabilities, "power")
		staticMeta["power_actions"] = "reboot,shutdown"
	}
	if sessionType := strings.TrimSpace(webrtcCaps.DesktopSessionType); sessionType != "" {
		staticMeta["desktop_session_type"] = sessionType
	}
	if backend := strings.TrimSpace(webrtcCaps.DesktopBackend); backend != "" {
		staticMeta["desktop_backend"] = backend
	}
	if captureBackend := strings.TrimSpace(webrtcCaps.CaptureBackend); captureBackend != "" {
		staticMeta["desktop_capture_backend"] = captureBackend
	}
	staticMeta["desktop_vnc_real_desktop_supported"] = fmt.Sprintf("%v", webrtcCaps.VNCRealDesktopSupported)
	staticMeta["desktop_webrtc_real_desktop_supported"] = fmt.Sprintf("%v", webrtcCaps.WebRTCRealDesktopSupported)
	if webrtcCaps.Available {
		capabilities = append(capabilities, "webrtc")
		staticMeta["webrtc_available"] = "true"
		delete(staticMeta, "webrtc_unavailable_reason")
		if len(webrtcCaps.VideoEncoders) > 0 {
			staticMeta["webrtc_video_encoders"] = strings.Join(webrtcCaps.VideoEncoders, ",")
		}
		if len(webrtcCaps.AudioSources) > 0 {
			staticMeta["webrtc_audio_sources"] = strings.Join(webrtcCaps.AudioSources, ",")
		}
	} else {
		staticMeta["webrtc_available"] = "false"
		if reason := strings.TrimSpace(webrtcCaps.UnavailableReason); reason != "" {
			staticMeta["webrtc_unavailable_reason"] = reason
		}
	}
	if identity != nil {
		staticMeta["agent_device_fingerprint"] = identity.Fingerprint
		staticMeta["agent_device_key_alg"] = identity.KeyAlgorithm
	}
	runtimeIdentity := newRuntimeIdentitySource(cfg)
	// From this point onward the shared runtime identity source is the only
	// long-lived bearer owner. Config copies retain static behavior settings but
	// must not pin a credential that enrollment or recovery can replace.
	cfg.APIToken = ""
	httpPublisher := newHeartbeatPublisherWithRuntimeIdentity(cfg, staticMeta, runtimeIdentity)

	var publisher HeartbeatPublisher
	var transport *wsTransport

	if cfg.WSBaseURL != "" {
		platform := ""
		if meta := staticMeta; meta != nil {
			platform = meta["platform"]
		}

		transport = newWSTransportWithRuntimeIdentity(runtimeIdentity, platform, cfg.Version, buildTLSConfig(&cfg), cfg.TokenFilePath, identity)
		transport.setCredentialPersistenceError(credentialWarning)
		transport.setCredentialError(credentialError)

		// Set re-enrollment callback if enrollment token is configured.
		if cfg.EnrollmentToken != "" {
			transport.reEnrollFn = func() (string, error) {
				return reEnrollAgainstActiveHub(ctx, cfg, transport)
			}
		}

		// Start network change monitor.
		networkCh := make(chan struct{}, 1)
		transport.networkChanged = networkCh
		netMon := newNetworkMonitor(networkCh)
		go netMon.Run(ctx)

		// Buffer for telemetry samples during disconnection.
		telemetryBuf := NewRingBuffer[TelemetrySample](60)

		publisher = newWSHeartbeatPublisher(transport, httpPublisher, cfg, staticMeta, capabilities)

		// Store buffer reference in runtime for telemetry buffering during disconnect.
		runtime := newRuntimeWithIdentity(cfg, provider, publisher, runtimeIdentity)
		runtime.transport = transport
		runtime.telemetryBuf = telemetryBuf
		runtime.deviceIdentity = identity

		go RunWatchdog(ctx, WatchdogConfig{
			HeartbeatCounter: &runtime.HeartbeatCounter,
			ExitFunc:         os.Exit,
		})

		// Docker and web service collectors: declared here (before reconnect loop)
		// so the onConnect closure can reference them for state resets.
		var dockerCollector *dockerpkg.DockerCollector
		var execMgr *dockerpkg.DockerExecManager
		var dockerLogMgr *dockerpkg.DockerLogManager
		var webServiceCollector *WebServiceCollector

		// Session managers: created before reconnect loop so onConnect can
		// close stale sessions from the previous connection.
		termMgr := newTerminalManager()
		dispMgr := newDisplayManager()
		deskMgr := newDesktopManager(dispMgr)
		fileMgr := files.NewManager(cfg.FileRootMode)
		webrtcMgr := newWebRTCManager(webrtcCaps, runtime, fileMgr, dispMgr)

		// Start reconnect loop in background.
		go transport.reconnectLoop(ctx, func() {
			replayBufferedTelemetry(transport, telemetryBuf)
			sendWebRTCCapabilities(transport, webrtcCaps)
			sendAgentSettingsState(transport, runtime, time.Now().UTC().Format(time.RFC3339Nano))
			if dockerCollector != nil {
				dockerCollector.ResetPublishedState()
			}
			if webServiceCollector != nil {
				webServiceCollector.ResetPublishedState()
			}
			// Close stale sessions from the previous connection — the hub
			// has no knowledge of them after reconnect.
			termMgr.CloseAll()
			deskMgr.CloseAll()
			webrtcMgr.CloseAll()
		})

		// Load persisted config overrides from disk.
		loadPersistedConfig(runtime)
		processMgr := system.NewProcessManager()
		serviceMgr := backends.NewServiceManager()
		journalMgr := backends.NewJournalManager()
		diskMgr := system.NewDiskManager()
		networkMgr := newNetworkManager()
		packageMgr := backends.NewPackageManager()
		cronMgr := backends.NewCronManager()
		usersMgr := system.NewUsersManager()
		clipMgr := newClipboardManager()
		audioMgr := newAudioSidebandManager()
		dockerMode := strings.TrimSpace(strings.ToLower(cfg.DockerEnabled))
		if dockerMode == "" {
			dockerMode = "auto"
		}
		if dockerMode == "false" {
			log.Printf("%s: Docker collector disabled by configuration", cfg.Name)
		} else {
			dockerCollector = dockerpkg.NewDockerCollector(cfg.DockerSocket, transport, cfg.AssetID, cfg.DockerDiscoveryInterval)
			dockerCollector.SetAssetIDProvider(runtimeIdentity.AssetID)
			if dockerCollector.IsAvailable() {
				execMgr = dockerCollector.NewExecManager()
				dockerLogMgr = dockerCollector.NewLogManager()
				go dockerCollector.Run(ctx)
				log.Printf("%s: Docker collector enabled (%s): %s", cfg.Name, dockerMode, cfg.DockerSocket)
			} else {
				dockerCollector = nil
				if dockerMode == "true" {
					log.Printf("%s: Docker collector explicitly enabled but endpoint unavailable: %s", cfg.Name, cfg.DockerSocket)
				} else {
					log.Printf("%s: Docker endpoint not available at %s, Docker collector disabled", cfg.Name, cfg.DockerSocket)
				}
			}
		}

		// Web service collector: discovers web services from Docker containers.
		hostIP := resolveHostIP()
		webServiceCollector = NewWebServiceCollector(transport, cfg.AssetID, hostIP, cfg.WebServiceDiscoveryInterval, dockerCollector, WebServiceDiscoveryConfig{
			DockerEnabled:            cfg.ServicesDiscoveryDockerEnabled,
			ProxyEnabled:             cfg.ServicesDiscoveryProxyEnabled,
			ProxyTraefikEnabled:      cfg.ServicesDiscoveryProxyTraefikEnabled,
			ProxyCaddyEnabled:        cfg.ServicesDiscoveryProxyCaddyEnabled,
			ProxyNPMEnabled:          cfg.ServicesDiscoveryProxyNPMEnabled,
			PortScanEnabled:          cfg.ServicesDiscoveryPortScanEnabled,
			PortScanIncludeListening: cfg.ServicesDiscoveryPortScanIncludeListening,
			PortScanPorts:            cfg.ServicesDiscoveryPortScanPorts,
			LANScanEnabled:           cfg.ServicesDiscoveryLANScanEnabled,
			LANScanCIDRs:             cfg.ServicesDiscoveryLANScanCIDRs,
			LANScanPorts:             cfg.ServicesDiscoveryLANScanPorts,
			LANScanMaxHosts:          cfg.ServicesDiscoveryLANScanMaxHosts,
		})
		webServiceCollector.SetAssetIDProvider(runtimeIdentity.AssetID)
		go webServiceCollector.Run(ctx)
		log.Printf("%s: Web service collector enabled (host IP: %s)", cfg.Name, hostIP)

		go receiveLoop(ctx, transport, cfg, runtime, termMgr, deskMgr, webrtcMgr, fileMgr, processMgr, serviceMgr, journalMgr, diskMgr, networkMgr, packageMgr, cronMgr, usersMgr, clipMgr, audioMgr, dockerCollector, webServiceCollector, execMgr, dockerLogMgr)

		// Start log producer — runs independently of receiveLoop, pushing
		// journalctl entries to the hub as MsgLogBatch messages.
		if cfg.LogStreamEnabled {
			logMgr := backends.NewLogManager()
			defer logMgr.CloseAll()
			go logMgr.Start(ctx, transport)
		} else {
			log.Printf("%s: background log streaming disabled (LABTETHER_LOG_STREAM_ENABLED=false)", cfg.Name)
		}

		log.Printf("%s: WebSocket transport configured: %s", cfg.Name, cfg.WSBaseURL)

		return runtime.Run(ctx)
	}

	publisher = httpPublisher
	runtime := newRuntimeWithIdentity(cfg, provider, publisher, runtimeIdentity)
	runtime.deviceIdentity = identity
	go RunWatchdog(ctx, WatchdogConfig{
		HeartbeatCounter: &runtime.HeartbeatCounter,
		ExitFunc:         os.Exit,
	})
	return runtime.Run(ctx)
}

// reEnrollAgainstActiveHub performs a real enrollment request against the
// origin of the WebSocket connection that just rejected the current token.
// It deliberately bypasses ResolveToken: that resolver prefers the persisted
// token file, which is exactly the stale credential re-enrollment must replace.
func reEnrollAgainstActiveHub(ctx context.Context, cfg RuntimeConfig, transport *wsTransport) (string, error) {
	if transport == nil {
		return "", fmt.Errorf("re-enrollment transport is unavailable")
	}
	if strings.TrimSpace(cfg.EnrollmentToken) == "" {
		return "", fmt.Errorf("re-enrollment token is unavailable")
	}

	currentIdentity := transport.identitySource().Snapshot()
	activeWSURL := currentIdentity.WSBaseURL
	canonicalAssetID := canonicalEnrollmentAssetID(currentIdentity.AssetID)
	if strings.TrimSpace(activeWSURL) == "" {
		return "", fmt.Errorf("re-enrollment websocket URL is unavailable")
	}
	if canonicalAssetID == "" {
		return "", fmt.Errorf("re-enrollment asset id is unavailable")
	}

	cfgCopy := cfg
	cfgCopy.APIToken = ""
	// APIBaseURL may still name a previous hub. Derive the enrollment endpoint
	// from the active, failed WebSocket origin so the returned token is valid for
	// the connection that will be retried.
	cfgCopy.APIBaseURL = ""
	cfgCopy.WSBaseURL = activeWSURL
	resp, err := enrollWithHubWithContinuityIdentity(ctx, &cfgCopy, transport.deviceIdentity, canonicalAssetID)
	if err != nil {
		return "", err
	}
	resp.AgentToken = strings.TrimSpace(resp.AgentToken)
	resp.AssetID = strings.TrimSpace(resp.AssetID)
	if resp.AgentToken == "" {
		return "", fmt.Errorf("re-enrollment returned empty token")
	}
	if resp.AssetID == "" {
		return "", fmt.Errorf("re-enrollment returned empty asset id")
	}

	// Adopt the complete token-bound identity before reconnecting. This single
	// update also moves HTTP fallback to the active/reported API origin.
	responseWSURL := normalizeWSBaseURL(resp.HubWSURL)
	if responseWSURL == "" {
		responseWSURL = activeWSURL
	}
	adoptedIdentity, err := transport.identitySource().AdoptCredential(
		resp.AgentToken,
		resp.AssetID,
		responseWSURL,
		normalizeAPIBaseURL(resp.HubAPIURL),
	)
	if err != nil {
		return "", err
	}

	// A persistence error must not discard the in-memory token the hub has
	// already issued. Remove any stale on-disk credential, keep the replacement
	// for this runtime, and surface a durable local-status warning.
	credentialWarning := ""
	if cfg.TokenFilePath != "" {
		if err := saveTokenToFile(cfg.TokenFilePath, resp.AgentToken); err != nil {
			credentialWarning = agentTokenPersistenceFailed
			if removeErr := removePersistedAgentToken(cfg.TokenFilePath); removeErr != nil {
				log.Printf("agentws: ERROR: replacement token is memory-only and stale token removal also failed: persist=%v remove=%v", err, removeErr)
			} else {
				log.Printf("agentws: ERROR: replacement token is memory-only; stale token file removed after persistence failure: %v", err)
			}
		} else {
			if err := saveEnrollmentState(cfg.TokenFilePath, enrollmentState{
				AssetID:   adoptedIdentity.AssetID,
				HubWSURL:  adoptedIdentity.WSBaseURL,
				HubAPIURL: adoptedIdentity.APIBaseURL,
			}); err != nil {
				log.Printf("agentws: warning: failed to persist re-enrollment state: %v", err)
			}
		}
	}

	// The one-time token has been consumed by the hub. Remove its file/env
	// source and disarm further retries even if persisting the replacement
	// credential failed; retrying a consumed bearer can never recover.
	if err := discardConsumedEnrollmentToken(&cfgCopy); err != nil {
		if credentialWarning == "" {
			credentialWarning = "consumed_enrollment_token_cleanup_failed"
		} else {
			credentialWarning += ",consumed_enrollment_token_cleanup_failed"
		}
		log.Printf("agentws: ERROR: consumed re-enrollment token cleanup failed: %v", err)
	}
	transport.mu.Lock()
	transport.reEnrollFn = nil
	transport.mu.Unlock()
	transport.setCredentialPersistenceError(credentialWarning)

	// transport.updateToken() is called by the reconnect loop after this
	// returns, resetting the auth-failure state atomically with token adoption.
	return resp.AgentToken, nil
}

// canonicalEnrollmentAssetID mirrors the Hub's hostname-to-asset normalization
// for an already validated runtime asset ID. Continuity proof v2 is verified
// against that canonical value, not the original hostname casing.
func canonicalEnrollmentAssetID(assetID string) string {
	const maxAssetIDBytes = 64

	canonical := strings.ToLower(strings.TrimSpace(assetID))
	if len(canonical) > maxAssetIDBytes {
		canonical = canonical[:maxAssetIDBytes]
	}
	var normalized strings.Builder
	normalized.Grow(len(canonical))
	for _, ch := range canonical {
		switch {
		case ch >= 'a' && ch <= 'z':
			normalized.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			normalized.WriteRune(ch)
		case ch == '-' || ch == '_' || ch == '.':
			normalized.WriteRune(ch)
		default:
			normalized.WriteByte('-')
		}
	}
	return strings.Trim(normalized.String(), "-")
}

func replayBufferedTelemetry(transport *wsTransport, telemetryBuf *RingBuffer[TelemetrySample]) {
	if transport == nil || telemetryBuf == nil {
		return
	}

	buffered := telemetryBuf.Drain()
	if len(buffered) == 0 {
		return
	}

	log.Printf("agentws: replaying %d buffered telemetry samples", len(buffered))
	for _, sample := range buffered {
		sendTelemetrySample(transport, sample)
	}
}

func sendWebRTCCapabilities(transport *wsTransport, caps protocol.WebRTCCapabilitiesData) {
	if transport == nil || !transport.Connected() {
		return
	}
	data, err := json.Marshal(caps)
	if err != nil {
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgWebRTCCapabilities,
		Data: data,
	})
}
