package remoteaccess

import (
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
)

const (
	DefaultCommandTimeout   = 30 * time.Second
	MaxRemoteCommandTimeout = 5 * time.Minute
	MaxCommandOutputBytes   = sysconfig.MaxCommandOutputBytes
)

// TruncateCommandOutput delegates to sysconfig.TruncateCommandOutput.
var TruncateCommandOutput = sysconfig.TruncateCommandOutput

func remoteCommandTimeoutFromSeconds(seconds int) time.Duration {
	if seconds <= 0 {
		return DefaultCommandTimeout
	}
	maxSeconds := int(MaxRemoteCommandTimeout / time.Second)
	if seconds > maxSeconds {
		return MaxRemoteCommandTimeout
	}
	return time.Duration(seconds) * time.Second
}
