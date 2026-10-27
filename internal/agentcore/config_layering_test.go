package agentcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAgentSettingsFileCanonicalizesMixedCaseKeys(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "agent-settings.json")
	payload := struct {
		Version   int               `json:"version"`
		Values    map[string]string `json:"values"`
		UpdatedAt string            `json:"updated_at"`
	}{
		Version: 1,
		Values: map[string]string{
			"Docker_Enabled":       "TRUE",
			"Collect_Interval_Sec": "45",
			"Log_Level":            "DEBUG",
		},
		UpdatedAt: "2026-03-09T00:00:00Z",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal settings payload: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatalf("write settings payload: %v", err)
	}

	values, err := LoadAgentSettingsFile(settingsPath)
	if err != nil {
		t.Fatalf("load settings file: %v", err)
	}
	if values[SettingKeyDockerEnabled] != "true" {
		t.Fatalf("docker_enabled=%q, want true", values[SettingKeyDockerEnabled])
	}
	if values[SettingKeyCollectIntervalSec] != "45" {
		t.Fatalf("collect_interval_sec=%q, want 45", values[SettingKeyCollectIntervalSec])
	}
	if values[SettingKeyLogLevel] != "debug" {
		t.Fatalf("log_level=%q, want debug", values[SettingKeyLogLevel])
	}
	if _, ok := values["Docker_Enabled"]; ok {
		t.Fatalf("unexpected mixed-case key in loaded values: %+v", values)
	}
}

// Install-time choices in the environment must survive values that earlier
// Hub pushes saved to agent-config.json (audit finding 1: a Hub default
// replaced the installer's Docker endpoint after the next restart). Settings
// without an environment choice still come from the file.
func TestLoadConfigEnvironmentChoicesBeatSettingsFile(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "agent-settings.json")
	payload := struct {
		Version   int               `json:"version"`
		Values    map[string]string `json:"values"`
		UpdatedAt string            `json:"updated_at"`
	}{
		Version: 1,
		Values: map[string]string{
			"Collect_Interval_Sec":              "45",
			"Heartbeat_Interval_Sec":            "90",
			"Docker_Enabled":                    "auto",
			"Docker_Endpoint":                   "/var/run/docker.sock",
			"Files_Root_Mode":                   "home",
			"Services_Discovery_Docker_Enabled": "false",
			"Allow_Remote_Overrides":            "true",
			"Log_Level":                         "DEBUG",
		},
		UpdatedAt: "2026-03-09T00:00:00Z",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal settings payload: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatalf("write settings payload: %v", err)
	}

	t.Setenv("LABTETHER_AGENT_SETTINGS_FILE", settingsPath)
	t.Setenv("LABTETHER_TOKEN_FILE", filepath.Join(dir, "agent-token"))
	t.Setenv("AGENT_COLLECT_INTERVAL", "12")
	t.Setenv("AGENT_HEARTBEAT_INTERVAL", "")
	t.Setenv("LABTETHER_LOW_POWER_MODE", "")
	t.Setenv("LABTETHER_DOCKER_ENABLED", "true")
	t.Setenv("LABTETHER_DOCKER_SOCKET", "/srv/docker/docker.sock")
	t.Setenv("LABTETHER_FILES_ROOT_MODE", "full")
	t.Setenv("LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED", "true")
	t.Setenv("LABTETHER_ALLOW_REMOTE_OVERRIDES", "false")
	t.Setenv("LABTETHER_LOG_LEVEL", "")

	cfg := LoadConfig("test-agent", "8090", "test")

	if cfg.CollectInterval != 12*time.Second {
		t.Fatalf("CollectInterval=%v, want install-time 12s", cfg.CollectInterval)
	}
	if cfg.DockerEnabled != "true" || cfg.DockerSocket != "/srv/docker/docker.sock" {
		t.Fatalf("Docker=%q %q, want install-time true /srv/docker/docker.sock", cfg.DockerEnabled, cfg.DockerSocket)
	}
	if cfg.FileRootMode != "full" {
		t.Fatalf("FileRootMode=%q, want install-time full", cfg.FileRootMode)
	}
	if !cfg.ServicesDiscoveryDockerEnabled {
		t.Fatalf("expected install-time ServicesDiscoveryDockerEnabled=true")
	}
	if cfg.HeartbeatInterval != 90*time.Second {
		t.Fatalf("HeartbeatInterval=%v, want 90s from the settings file", cfg.HeartbeatInterval)
	}
	if !cfg.AllowRemoteOverrides {
		t.Fatalf("expected AllowRemoteOverrides=true from settings file")
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel=%q, want debug from the settings file", cfg.LogLevel)
	}
}

// A Hub push must not replace an install-time choice, and must not save it
// to agent-config.json where it would win at the next start.
func TestApplyAgentSettingsKeepsInstallTimeChoices(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "agent-config.json")
	rt := NewRuntime(RuntimeConfig{
		DockerEnabled:     "true",
		DockerSocket:      "/srv/docker/docker.sock",
		LogLevel:          "info",
		AgentSettingsPath: settingsPath,
		envPinnedSettings: map[string]bool{SettingKeyDockerEnabled: true, SettingKeyDockerEndpoint: true},
	}, stubProvider{}, noopHeartbeatPublisher{})

	applied, _, err := rt.applyAgentSettings(map[string]string{
		SettingKeyDockerEnabled:  "auto",
		SettingKeyDockerEndpoint: "/var/run/docker.sock",
		SettingKeyLogLevel:       "debug",
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := applied[SettingKeyDockerEnabled]; ok {
		t.Fatalf("install-time docker_enabled was applied: %+v", applied)
	}
	if applied[SettingKeyLogLevel] != "debug" {
		t.Fatalf("Hub-managed log_level was not applied: %+v", applied)
	}
	reported := rt.ReportedAgentSettings()
	if reported[SettingKeyDockerEnabled] != "true" || reported[SettingKeyDockerEndpoint] != "/srv/docker/docker.sock" {
		t.Fatalf("reported docker settings = %q %q", reported[SettingKeyDockerEnabled], reported[SettingKeyDockerEndpoint])
	}
	saved, err := LoadAgentSettingsFile(settingsPath)
	if err != nil {
		t.Fatalf("load saved settings: %v", err)
	}
	if _, ok := saved[SettingKeyDockerEnabled]; ok {
		t.Fatalf("install-time key was saved from a Hub push: %+v", saved)
	}
}

func TestLoadConfigSettingsFileRejectsOutOfRangeIntervalsBeforeDurationConversion(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "agent-settings.json")
	payload := struct {
		Version   int               `json:"version"`
		Values    map[string]string `json:"values"`
		UpdatedAt string            `json:"updated_at"`
	}{
		Version: 1,
		Values: map[string]string{
			"Collect_Interval_Sec":          "2147483647",
			"Heartbeat_Interval_Sec":        "2147483647",
			"Docker_Discovery_Interval_Sec": "2147483647",
		},
		UpdatedAt: "2026-03-09T00:00:00Z",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal settings payload: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatalf("write settings payload: %v", err)
	}

	t.Setenv("LABTETHER_AGENT_SETTINGS_FILE", settingsPath)
	t.Setenv("AGENT_COLLECT_INTERVAL", "12")
	t.Setenv("AGENT_HEARTBEAT_INTERVAL", "30")
	t.Setenv("LABTETHER_DOCKER_DISCOVERY_INTERVAL", "40")

	cfg := LoadConfig("test-agent", "8090", "test")

	if cfg.CollectInterval != 12*time.Second {
		t.Fatalf("CollectInterval=%v, want env fallback 12s", cfg.CollectInterval)
	}
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Fatalf("HeartbeatInterval=%v, want env fallback 30s", cfg.HeartbeatInterval)
	}
	if cfg.DockerDiscoveryInterval != 40*time.Second {
		t.Fatalf("DockerDiscoveryInterval=%v, want env fallback 40s", cfg.DockerDiscoveryInterval)
	}
}

func TestLoadConfigExplicitSecretsBeatFileSecrets(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "agent-token")
	enrollmentFile := filepath.Join(dir, "enrollment-token")
	turnPassFile := filepath.Join(dir, "turn-pass")

	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if err := os.WriteFile(enrollmentFile, []byte("file-enroll\n"), 0o600); err != nil {
		t.Fatalf("write enrollment file: %v", err)
	}
	if err := os.WriteFile(turnPassFile, []byte("file-turn\n"), 0o600); err != nil {
		t.Fatalf("write turn pass file: %v", err)
	}

	t.Setenv("LABTETHER_TOKEN_FILE", tokenFile)
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN_FILE", enrollmentFile)
	t.Setenv("LABTETHER_WEBRTC_TURN_PASS_FILE", turnPassFile)
	t.Setenv("LABTETHER_AGENT_SETTINGS_FILE", filepath.Join(dir, "agent-settings.json"))
	t.Setenv("LABTETHER_API_TOKEN", "env-token")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "env-enroll")
	t.Setenv("LABTETHER_WEBRTC_TURN_PASS", "env-turn")

	cfg := LoadConfig("test-agent", "8090", "test")

	if cfg.APIToken != "env-token" {
		t.Fatalf("APIToken=%q, want env-token", cfg.APIToken)
	}
	if cfg.EnrollmentToken != "env-enroll" {
		t.Fatalf("EnrollmentToken=%q, want env-enroll", cfg.EnrollmentToken)
	}
	if cfg.WebRTCTURNPass != "env-turn" {
		t.Fatalf("WebRTCTURNPass=%q, want env-turn", cfg.WebRTCTURNPass)
	}
}
