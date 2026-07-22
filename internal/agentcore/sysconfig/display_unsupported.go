package sysconfig

import (
	"fmt"
	"strings"

	"github.com/labtether/protocol"
)

func unsupportedPlatformDisplays(goos string) ([]protocol.DisplayInfo, error) {
	platform := strings.TrimSpace(goos)
	if platform == "" {
		platform = "unknown"
	}
	return []protocol.DisplayInfo{}, fmt.Errorf("display enumeration is not supported on %s", platform)
}
