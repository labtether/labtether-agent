//go:build !windows

package system

import (
	"errors"

	"github.com/labtether/protocol"
)

func collectMountsWindows() ([]protocol.MountInfo, error) {
	return nil, errors.New("Windows volume collection is unavailable on this platform")
}
