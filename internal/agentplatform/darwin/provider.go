package darwin

import (
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore"
	"github.com/labtether/labtether-agent/internal/agentplatform/generic"
)

type Provider struct {
	base           *generic.Provider
	staticMetadata map[string]string
}

func New(assetID, source string) *Provider {
	base := generic.New(assetID, source, "launchd-helper")
	metadata := base.StaticMetadata()
	for key, value := range readTailscaleMetadata() {
		metadata[key] = value
	}
	for key, value := range readCapabilityMetadata() {
		metadata[key] = value
	}
	applyMacOSName(metadata)

	return &Provider{
		base:           base,
		staticMetadata: metadata,
	}
}

func (p *Provider) AgentInfo() agentcore.AgentInfo {
	return p.base.AgentInfo()
}

func (p *Provider) StaticMetadata() map[string]string {
	out := make(map[string]string, len(p.staticMetadata))
	for key, value := range p.staticMetadata {
		out[key] = value
	}
	return out
}

func (p *Provider) Collect(now time.Time) (agentcore.TelemetrySample, error) {
	return p.base.Collect(now)
}

// applyMacOSName names the system "macOS" where gopsutil reports the kernel's
// "darwin", so device pages read "macOS 27.2" as Windows ones read "Microsoft
// Windows 11 Pro". The platform key stays "darwin".
func applyMacOSName(metadata map[string]string) {
	if !strings.EqualFold(strings.TrimSpace(metadata["os_name"]), "darwin") {
		return
	}
	metadata["os_name"] = "macOS"
	metadata["os_pretty_name"] = strings.TrimSpace("macOS " + strings.TrimSpace(metadata["os_version"]))
}
