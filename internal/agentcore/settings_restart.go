package agentcore

import (
	"encoding/json"
	"log"
	"maps"
	"os"
	"slices"
	"strings"
	"time"
)

// restartSettingKeys are read once at start: by the Docker and web service
// collectors, and by the WebRTC capability check sent to the Hub on connect.
// A new value takes effect only after the agent restarts. Every other
// Hub-managed setting is applied while the agent runs.
var restartSettingKeys = []string{
	SettingKeyDockerEnabled,
	SettingKeyDockerEndpoint,
	SettingKeyDockerDiscoveryIntervalSec,
	SettingKeyServicesDiscoveryDockerEnabled,
	SettingKeyServicesDiscoveryProxyEnabled,
	SettingKeyServicesDiscoveryProxyTraefikEnabled,
	SettingKeyServicesDiscoveryProxyCaddyEnabled,
	SettingKeyServicesDiscoveryProxyNPMEnabled,
	SettingKeyServicesDiscoveryPortScanEnabled,
	SettingKeyServicesDiscoveryPortScanIncludeListening,
	SettingKeyServicesDiscoveryPortScanPorts,
	SettingKeyServicesDiscoveryLANScanEnabled,
	SettingKeyServicesDiscoveryLANScanCIDRs,
	SettingKeyServicesDiscoveryLANScanPorts,
	SettingKeyServicesDiscoveryLANScanMaxHosts,
	SettingKeyWebRTCEnabled,
	SettingKeyWebRTCWaylandExperimentalEnabled,
	SettingKeyWebRTCWaylandPipeWireNodeID,
	SettingKeyWebRTCWaylandInputBackend,
}

// settingsRestartDelay lets agent.settings.applied and the state report
// reach the Hub before the agent stops.
var settingsRestartDelay = 2 * time.Second

const (
	// settingsRestartRepeatWindow stops a restart loop: if the same values
	// still differ this soon after a restart for them, the agent stays up.
	settingsRestartRepeatWindow   = 10 * time.Minute
	maxSettingsRestartRecordBytes = 64 * 1024
)

// startupRestartSettings returns the values the running components were
// built with, for the settings that need a restart.
func startupRestartSettings(cfg RuntimeConfig) map[string]string {
	all := AgentSettingValuesFromConfigSnapshot(configSnapshotFromRuntimeConfig(cfg))
	running := make(map[string]string, len(restartSettingKeys))
	for _, key := range restartSettingKeys {
		running[key] = all[key]
	}
	return running
}

// pendingRestartSettingsLocked lists the restart-only settings whose saved
// value differs from the running one, with the saved value. r.mu must be held.
func (r *Runtime) pendingRestartSettingsLocked() map[string]string {
	saved := AgentSettingValuesFromConfigSnapshot(configSnapshotFromRuntimeConfig(r.cfg))
	pending := make(map[string]string)
	for key, running := range r.runningSettings {
		if saved[key] != running {
			pending[key] = saved[key]
		}
	}
	return pending
}

// restartForSettings restarts the agent through its service manager so the
// pending restart-only settings take effect. When no service manager would
// start it again, or the new values are not safely saved, the agent keeps
// running and keeps reporting its running values with restart_required.
func (r *Runtime) restartForSettings() {
	r.mu.RLock()
	pending := r.pendingRestartSettingsLocked()
	settingsPath := r.cfg.AgentSettingsPath
	restart := r.restartAgent
	r.mu.RUnlock()
	if len(pending) == 0 {
		return
	}
	names := strings.Join(slices.Sorted(maps.Keys(pending)), ", ")
	if restart == nil {
		log.Printf("agent settings: restart the agent to use the new %s", names)
		return
	}
	if !pendingSettingsSaved(settingsPath, pending) {
		log.Printf("agent settings: %s could not be confirmed in %s; restart the agent after fixing the file", names, settingsPath)
		return
	}
	recordPath := settingsPath + ".restart"
	if restartedForSameSettings(recordPath, pending) {
		log.Printf("agent settings: %s still differ after a restart for them; not restarting again", names)
		return
	}
	if err := recordSettingsRestart(recordPath, pending); err != nil {
		log.Printf("agent settings: not restarting for %s: %v", names, err)
		return
	}
	log.Printf("agent settings: restarting to use the new %s", names)
	time.AfterFunc(settingsRestartDelay, func() {
		if err := restart(); err != nil {
			log.Printf("agent settings: restart failed: %v; restart the agent to use the new %s", err, names)
		}
	})
}

// pendingSettingsSaved confirms the next start reads the new values, so a
// restart cannot come back with the old ones and restart again.
func pendingSettingsSaved(path string, pending map[string]string) bool {
	saved, err := LoadAgentSettingsFile(path)
	if err != nil || strings.TrimSpace(path) == "" {
		return false
	}
	for key, value := range pending {
		if saved[key] != value {
			return false
		}
	}
	return true
}

type settingsRestartRecord struct {
	Values map[string]string `json:"values"`
	At     time.Time         `json:"at"`
}

func restartedForSameSettings(path string, pending map[string]string) bool {
	data, err := readBoundedRegularFile(path, maxSettingsRestartRecordBytes)
	if err != nil {
		return false
	}
	var record settingsRestartRecord
	if json.Unmarshal(data, &record) != nil {
		return false
	}
	return time.Since(record.At) < settingsRestartRepeatWindow && maps.Equal(record.Values, pending)
}

func recordSettingsRestart(path string, pending map[string]string) error {
	data, err := json.Marshal(settingsRestartRecord{Values: pending, At: time.Now().UTC()})
	if err != nil {
		return err
	}
	return writeManagedFileAtomic(path, data, 0o600, true)
}

// nativeAppManaged reports whether a native macOS or Windows app runs this
// agent as its child. The app owns the agent's lifecycle, so the agent never
// restarts itself there.
func nativeAppManaged() bool {
	return strings.TrimSpace(os.Getenv(envNativeWrapperParentPID)) != ""
}
