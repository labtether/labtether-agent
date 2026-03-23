//go:build freebsd

package agentplatform

import (
	"github.com/labtether/labtether-agent/internal/agentcore"
	"github.com/labtether/labtether-agent/internal/agentplatform/freebsd"
	"github.com/labtether/labtether-agent/internal/platforms"
)

func init() {
	providerFactories[platforms.FreeBSD] = func(assetID, source string) agentcore.TelemetryProvider {
		return freebsd.New(assetID, source)
	}
}
