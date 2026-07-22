//go:build !windows

package backends

import (
	"fmt"

	"github.com/labtether/protocol"
)

func listWindowsRegistryPackages() ([]protocol.PackageInfo, error) {
	return nil, fmt.Errorf("Windows package registry inventory is unavailable on this platform")
}
