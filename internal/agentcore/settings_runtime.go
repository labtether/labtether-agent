package agentcore

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (r *Runtime) ReportedAgentSettings() map[string]string {
	if r == nil {
		return map[string]string{}
	}

	r.mu.RLock()
	cfgCopy := r.cfg
	running := r.runningSettings
	r.mu.RUnlock()

	values := AgentSettingValuesFromConfigSnapshot(configSnapshotFromRuntimeConfig(cfgCopy))
	// A saved value that needs a restart is not in use yet; report the one
	// the agent runs with until then.
	for key, value := range running {
		values[key] = value
	}
	values[SettingKeyCollectIntervalSec] = strconv.Itoa(r.effectiveCollectIntervalSec())
	values[SettingKeyHeartbeatIntervalSec] = strconv.Itoa(r.effectiveHeartbeatIntervalSec())
	return values
}

// configSnapshotFromRuntimeConfig maps RuntimeConfig to the ConfigSnapshot
// type expected by the sysconfig subpackage.
func configSnapshotFromRuntimeConfig(cfg RuntimeConfig) ConfigSnapshot {
	return ConfigSnapshot{
		CollectInterval:                           cfg.CollectInterval,
		HeartbeatInterval:                         cfg.HeartbeatInterval,
		DockerEnabled:                             cfg.DockerEnabled,
		DockerSocket:                              cfg.DockerSocket,
		DockerDiscoveryInterval:                   cfg.DockerDiscoveryInterval,
		ServicesDiscoveryDockerEnabled:            cfg.ServicesDiscoveryDockerEnabled,
		ServicesDiscoveryProxyEnabled:             cfg.ServicesDiscoveryProxyEnabled,
		ServicesDiscoveryProxyTraefikEnabled:      cfg.ServicesDiscoveryProxyTraefikEnabled,
		ServicesDiscoveryProxyCaddyEnabled:        cfg.ServicesDiscoveryProxyCaddyEnabled,
		ServicesDiscoveryProxyNPMEnabled:          cfg.ServicesDiscoveryProxyNPMEnabled,
		ServicesDiscoveryPortScanEnabled:          cfg.ServicesDiscoveryPortScanEnabled,
		ServicesDiscoveryPortScanIncludeListening: cfg.ServicesDiscoveryPortScanIncludeListening,
		ServicesDiscoveryPortScanPorts:            cfg.ServicesDiscoveryPortScanPorts,
		ServicesDiscoveryLANScanEnabled:           cfg.ServicesDiscoveryLANScanEnabled,
		ServicesDiscoveryLANScanCIDRs:             cfg.ServicesDiscoveryLANScanCIDRs,
		ServicesDiscoveryLANScanPorts:             cfg.ServicesDiscoveryLANScanPorts,
		ServicesDiscoveryLANScanMaxHosts:          cfg.ServicesDiscoveryLANScanMaxHosts,
		FileRootMode:                              cfg.FileRootMode,
		WebRTCEnabled:                             cfg.WebRTCEnabled,
		WebRTCSTUNURL:                             cfg.WebRTCSTUNURL,
		WebRTCTURNURL:                             cfg.WebRTCTURNURL,
		WebRTCTURNUser:                            cfg.WebRTCTURNUser,
		WebRTCTURNPass:                            cfg.WebRTCTURNPass,
		WebRTCWaylandExperimentalEnabled:          cfg.WebRTCWaylandExperimentalEnabled,
		WebRTCWaylandPipeWireNodeID:               cfg.WebRTCWaylandPipeWireNodeID,
		WebRTCWaylandInputBackend:                 cfg.WebRTCWaylandInputBackend,
		CaptureFPS:                                cfg.CaptureFPS,
		TLSSkipVerify:                             cfg.TLSSkipVerify,
		TLSCAFile:                                 cfg.TLSCAFile,
		AllowRemoteOverrides:                      cfg.AllowRemoteOverrides,
		LogLevel:                                  cfg.LogLevel,
	}
}

func (r *Runtime) effectiveCollectIntervalSec() int {
	if r == nil {
		return 0
	}
	if override := r.collectIntervalOverride.Load(); override > 0 {
		return int(override)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return int(durationSeconds(r.cfg.CollectInterval))
}

func (r *Runtime) effectiveHeartbeatIntervalSec() int {
	if r == nil {
		return 0
	}
	if override := r.heartbeatIntervalOverride.Load(); override > 0 {
		return int(override)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return int(durationSeconds(r.cfg.HeartbeatInterval))
}

func (r *Runtime) allowRemoteOverrides() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg.AllowRemoteOverrides
}

func (r *Runtime) applyAgentSettings(values map[string]string) (map[string]string, bool, error) {
	applied := make(map[string]string)
	if r == nil {
		return applied, false, nil
	}

	needsPersistedConfigWrite := false
	fileRootModeChanged := false
	var kept []string

	r.mu.Lock()
	for key, rawValue := range values {
		definition, ok := AgentSettingDefinitionByKey(key)
		if !ok {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("unknown setting key: %s", key)
		}
		if definition.LocalOnly {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("setting %s is local-only", key)
		}
		if r.cfg.settingPinned(definition.Key) {
			// Chosen at install time; the agent keeps its own value and
			// reports it in agent.settings.state.
			kept = append(kept, definition.Key)
			continue
		}
		normalized, err := NormalizeAgentSettingValue(key, rawValue)
		if err != nil {
			r.mu.Unlock()
			return nil, false, err
		}

		switch key {
		case SettingKeyCollectIntervalSec:
			seconds, _ := strconv.Atoi(normalized)
			r.collectIntervalOverride.Store(int64(seconds))
			r.cfg.CollectInterval = time.Duration(seconds) * time.Second
			r.baseCollectInterval = r.cfg.CollectInterval
			needsPersistedConfigWrite = true
		case SettingKeyHeartbeatIntervalSec:
			seconds, _ := strconv.Atoi(normalized)
			r.heartbeatIntervalOverride.Store(int64(seconds))
			r.cfg.HeartbeatInterval = time.Duration(seconds) * time.Second
			r.baseHeartbeatInterval = r.cfg.HeartbeatInterval
			needsPersistedConfigWrite = true
		case SettingKeyDockerEnabled:
			if !strings.EqualFold(strings.TrimSpace(r.cfg.DockerEnabled), normalized) {
				r.cfg.DockerEnabled = normalized
			}
		case SettingKeyDockerEndpoint:
			if strings.TrimSpace(r.cfg.DockerSocket) != normalized {
				r.cfg.DockerSocket = normalized
			}
		case SettingKeyDockerDiscoveryIntervalSec:
			seconds, _ := strconv.Atoi(normalized)
			nextInterval := time.Duration(seconds) * time.Second
			if r.cfg.DockerDiscoveryInterval != nextInterval {
				r.cfg.DockerDiscoveryInterval = nextInterval
			}
		case SettingKeyServicesDiscoveryDockerEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryDockerEnabled != enabled {
				r.cfg.ServicesDiscoveryDockerEnabled = enabled
			}
		case SettingKeyServicesDiscoveryProxyEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryProxyEnabled != enabled {
				r.cfg.ServicesDiscoveryProxyEnabled = enabled
			}
		case SettingKeyServicesDiscoveryProxyTraefikEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryProxyTraefikEnabled != enabled {
				r.cfg.ServicesDiscoveryProxyTraefikEnabled = enabled
			}
		case SettingKeyServicesDiscoveryProxyCaddyEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryProxyCaddyEnabled != enabled {
				r.cfg.ServicesDiscoveryProxyCaddyEnabled = enabled
			}
		case SettingKeyServicesDiscoveryProxyNPMEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryProxyNPMEnabled != enabled {
				r.cfg.ServicesDiscoveryProxyNPMEnabled = enabled
			}
		case SettingKeyServicesDiscoveryPortScanEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryPortScanEnabled != enabled {
				r.cfg.ServicesDiscoveryPortScanEnabled = enabled
			}
		case SettingKeyServicesDiscoveryPortScanIncludeListening:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryPortScanIncludeListening != enabled {
				r.cfg.ServicesDiscoveryPortScanIncludeListening = enabled
			}
		case SettingKeyServicesDiscoveryPortScanPorts:
			if strings.TrimSpace(r.cfg.ServicesDiscoveryPortScanPorts) != normalized {
				r.cfg.ServicesDiscoveryPortScanPorts = normalized
			}
		case SettingKeyServicesDiscoveryLANScanEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.ServicesDiscoveryLANScanEnabled != enabled {
				r.cfg.ServicesDiscoveryLANScanEnabled = enabled
			}
		case SettingKeyServicesDiscoveryLANScanCIDRs:
			if strings.TrimSpace(r.cfg.ServicesDiscoveryLANScanCIDRs) != normalized {
				r.cfg.ServicesDiscoveryLANScanCIDRs = normalized
			}
		case SettingKeyServicesDiscoveryLANScanPorts:
			if strings.TrimSpace(r.cfg.ServicesDiscoveryLANScanPorts) != normalized {
				r.cfg.ServicesDiscoveryLANScanPorts = normalized
			}
		case SettingKeyServicesDiscoveryLANScanMaxHosts:
			maxHosts, _ := strconv.Atoi(normalized)
			if r.cfg.ServicesDiscoveryLANScanMaxHosts != maxHosts {
				r.cfg.ServicesDiscoveryLANScanMaxHosts = maxHosts
			}
		case SettingKeyFilesRootMode:
			if !strings.EqualFold(strings.TrimSpace(r.cfg.FileRootMode), normalized) {
				r.cfg.FileRootMode = normalized
				fileRootModeChanged = true
			}
		case SettingKeyWebRTCEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.WebRTCEnabled != enabled {
				r.cfg.WebRTCEnabled = enabled
			}
		case SettingKeyWebRTCSTUNURL:
			if strings.TrimSpace(r.cfg.WebRTCSTUNURL) != normalized {
				r.cfg.WebRTCSTUNURL = normalized
			}
		case SettingKeyWebRTCTURNURL:
			if strings.TrimSpace(r.cfg.WebRTCTURNURL) != normalized {
				r.cfg.WebRTCTURNURL = normalized
			}
		case SettingKeyWebRTCTURNUser:
			if strings.TrimSpace(r.cfg.WebRTCTURNUser) != normalized {
				r.cfg.WebRTCTURNUser = normalized
			}
		case SettingKeyWebRTCTURNPass:
			if strings.TrimSpace(r.cfg.WebRTCTURNPass) != normalized {
				r.cfg.WebRTCTURNPass = normalized
			}
		case SettingKeyWebRTCWaylandExperimentalEnabled:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.WebRTCWaylandExperimentalEnabled != enabled {
				r.cfg.WebRTCWaylandExperimentalEnabled = enabled
			}
		case SettingKeyWebRTCWaylandPipeWireNodeID:
			if strings.TrimSpace(r.cfg.WebRTCWaylandPipeWireNodeID) != normalized {
				r.cfg.WebRTCWaylandPipeWireNodeID = normalized
			}
		case SettingKeyWebRTCWaylandInputBackend:
			if !strings.EqualFold(strings.TrimSpace(r.cfg.WebRTCWaylandInputBackend), normalized) {
				r.cfg.WebRTCWaylandInputBackend = normalized
			}
		case SettingKeyCaptureFPS:
			fps, _ := strconv.Atoi(normalized)
			if r.cfg.CaptureFPS != fps {
				r.cfg.CaptureFPS = fps
			}
		case SettingKeyAllowRemoteOverrides:
			enabled, _ := strconv.ParseBool(normalized)
			if r.cfg.AllowRemoteOverrides != enabled {
				r.cfg.AllowRemoteOverrides = enabled
			}
		case SettingKeyLogLevel:
			r.cfg.LogLevel = normalized
		}

		applied[key] = normalized
	}
	cfgCopy := r.cfg
	// Restart-only settings that differ from what the agent runs with; a
	// later push can also bring a value back to the running one.
	restartRequired := len(r.pendingRestartSettingsLocked()) > 0
	applyFileRootMode := r.applyFileRootMode
	r.mu.Unlock()

	if fileRootModeChanged && applyFileRootMode != nil {
		applyFileRootMode(cfgCopy.FileRootMode)
	}
	if len(kept) > 0 {
		sort.Strings(kept)
		log.Printf("agent settings: kept install-time values for %s; the Hub's values for these were not applied", strings.Join(kept, ", "))
	}
	if len(applied) == 0 {
		return applied, restartRequired, nil
	}

	fileValues, err := LoadAgentSettingsFile(cfgCopy.AgentSettingsPath)
	if err == nil {
		for key, value := range applied {
			fileValues[key] = value
		}
		if writeErr := SaveAgentSettingsFile(cfgCopy.AgentSettingsPath, fileValues); writeErr != nil {
			return nil, restartRequired, writeErr
		}
	}

	if needsPersistedConfigWrite {
		persistAppliedConfig(r)
	}
	setConnectorDiscoveryDockerConfig(cfgCopy.DockerEnabled, cfgCopy.DockerSocket)
	return applied, restartRequired, nil
}
