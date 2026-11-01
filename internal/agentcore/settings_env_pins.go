package agentcore

import (
	"os"
	"strings"
)

// installSettingEnvVars maps each Hub-managed setting to the environment
// variables an installer, service file or native app uses to choose it.
var installSettingEnvVars = map[string][]string{
	SettingKeyCollectIntervalSec:                        {"AGENT_COLLECT_INTERVAL"},
	SettingKeyHeartbeatIntervalSec:                      {"AGENT_HEARTBEAT_INTERVAL"},
	SettingKeyDockerEnabled:                             {"LABTETHER_DOCKER_ENABLED"},
	SettingKeyDockerEndpoint:                            {"LABTETHER_DOCKER_SOCKET"},
	SettingKeyDockerDiscoveryIntervalSec:                {"LABTETHER_DOCKER_DISCOVERY_INTERVAL"},
	SettingKeyServicesDiscoveryDockerEnabled:            {"LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED"},
	SettingKeyServicesDiscoveryProxyEnabled:             {"LABTETHER_SERVICES_DISCOVERY_PROXY_ENABLED", "LABTETHER_PROXY_DISABLED"},
	SettingKeyServicesDiscoveryProxyTraefikEnabled:      {"LABTETHER_SERVICES_DISCOVERY_PROXY_TRAEFIK_ENABLED"},
	SettingKeyServicesDiscoveryProxyCaddyEnabled:        {"LABTETHER_SERVICES_DISCOVERY_PROXY_CADDY_ENABLED"},
	SettingKeyServicesDiscoveryProxyNPMEnabled:          {"LABTETHER_SERVICES_DISCOVERY_PROXY_NPM_ENABLED"},
	SettingKeyServicesDiscoveryPortScanEnabled:          {"LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_ENABLED", "LABTETHER_WEBSVC_PORTSCAN_DISABLED"},
	SettingKeyServicesDiscoveryPortScanIncludeListening: {"LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_INCLUDE_LISTENING", "LABTETHER_WEBSVC_PORTSCAN_INCLUDE_LISTENING"},
	SettingKeyServicesDiscoveryPortScanPorts:            {"LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_PORTS", "LABTETHER_WEBSVC_PORTSCAN_PORTS"},
	SettingKeyServicesDiscoveryLANScanEnabled:           {"LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_ENABLED"},
	SettingKeyServicesDiscoveryLANScanCIDRs:             {"LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_CIDRS"},
	SettingKeyServicesDiscoveryLANScanPorts:             {"LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_PORTS"},
	SettingKeyServicesDiscoveryLANScanMaxHosts:          {"LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_MAX_HOSTS"},
	SettingKeyFilesRootMode:                             {"LABTETHER_FILES_ROOT_MODE"},
	SettingKeyWebRTCEnabled:                             {"LABTETHER_WEBRTC_ENABLED"},
	SettingKeyWebRTCSTUNURL:                             {"LABTETHER_WEBRTC_STUN_URL"},
	SettingKeyWebRTCTURNURL:                             {"LABTETHER_WEBRTC_TURN_URL"},
	SettingKeyWebRTCTURNUser:                            {"LABTETHER_WEBRTC_TURN_USER"},
	SettingKeyWebRTCTURNPass:                            {"LABTETHER_WEBRTC_TURN_PASS", "LABTETHER_WEBRTC_TURN_PASS_FILE"},
	SettingKeyWebRTCWaylandExperimentalEnabled:          {"LABTETHER_WEBRTC_WAYLAND_EXPERIMENTAL_ENABLED"},
	SettingKeyWebRTCWaylandPipeWireNodeID:               {"LABTETHER_WEBRTC_WAYLAND_PIPEWIRE_NODE_ID"},
	SettingKeyWebRTCWaylandInputBackend:                 {"LABTETHER_WEBRTC_WAYLAND_INPUT_BACKEND"},
	SettingKeyCaptureFPS:                                {"LABTETHER_CAPTURE_FPS"},
	SettingKeyLogLevel:                                  {"LABTETHER_LOG_LEVEL"},
}

// lowPowerSettingKeys are the Hub-managed settings whose defaults
// LABTETHER_LOW_POWER_MODE changes; turning it on chooses all of them.
var lowPowerSettingKeys = []string{
	SettingKeyCollectIntervalSec,
	SettingKeyHeartbeatIntervalSec,
	SettingKeyDockerDiscoveryIntervalSec,
	SettingKeyServicesDiscoveryPortScanEnabled,
	SettingKeyServicesDiscoveryPortScanIncludeListening,
}

// envPinnedSettings returns the Hub-managed settings chosen in the agent's
// environment at start, such as the installer's --docker-endpoint. These are
// install-time choices: Hub pushes skip them and agent-config.json, where
// earlier Hub pushes were saved, cannot override them.
func envPinnedSettings() map[string]bool {
	pinned := make(map[string]bool)
	for key, names := range installSettingEnvVars {
		for _, name := range names {
			if strings.TrimSpace(os.Getenv(name)) != "" {
				pinned[key] = true
				break
			}
		}
	}
	if parseBoolEnv("LABTETHER_LOW_POWER_MODE", false) {
		for _, key := range lowPowerSettingKeys {
			pinned[key] = true
		}
	}
	return pinned
}

// settingPinned reports whether key was chosen in the environment at start.
func (cfg RuntimeConfig) settingPinned(key string) bool {
	return cfg.envPinnedSettings[key]
}
