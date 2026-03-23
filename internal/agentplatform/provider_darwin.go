//go:build darwin

package agentplatform

import (
	"github.com/labtether/labtether-agent/internal/agentcore"
	"github.com/labtether/labtether-agent/internal/agentplatform/darwin"
	"github.com/labtether/labtether-agent/internal/platforms"
)

func init() {
	providerFactories[platforms.Darwin] = func(assetID, source string) agentcore.TelemetryProvider {
		return darwin.New(assetID, source)
	}
}
