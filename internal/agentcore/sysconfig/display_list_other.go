//go:build !linux && !darwin && !windows

package sysconfig

import (
	"runtime"

	"github.com/labtether/protocol"
)

// PlatformListDisplays reports display enumeration as unavailable on platforms
// without a real implementation. It must not invent a usable desktop.
func PlatformListDisplays() ([]protocol.DisplayInfo, error) {
	return unsupportedPlatformDisplays(runtime.GOOS)
}
