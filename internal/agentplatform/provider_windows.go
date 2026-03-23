//go:build windows

package agentplatform

import (
	"github.com/labtether/labtether-agent/internal/agentcore"
	"github.com/labtether/labtether-agent/internal/agentplatform/windows"
	"github.com/labtether/labtether-agent/internal/platforms"
)

func init() {
	providerFactories[platforms.Windows] = func(assetID, source string) agentcore.TelemetryProvider {
		return windows.New(assetID, source)
	}
}
