package agentcore

import (
	"os"
	"path/filepath"
	"strings"
)

// agentSecretPaths lists the agent's own credential and state locations,
// which allowlisted Hub commands (cat, grep, ...) may not read. The token's
// folder is included when it is a LabTether folder, such as /etc/labtether.
func agentSecretPaths(cfg RuntimeConfig) []string {
	paths := []string{
		cfg.TokenFilePath, cfg.EnrollmentTokenFilePath, cfg.AgentSettingsPath,
		cfg.DeviceKeyPath, cfg.WebRTCTURNPassFilePath, configDir(),
		strings.TrimSpace(os.Getenv(envAgentLocalAuthTokenFile)),
	}
	if token := strings.TrimSpace(cfg.TokenFilePath); token != "" {
		dir := filepath.Dir(token)
		if strings.Contains(strings.ToLower(filepath.Base(dir)), "labtether") {
			paths = append(paths, dir)
		}
	}
	return paths
}
