//go:build !linux && !darwin && !freebsd

package system

import (
	"fmt"

	"github.com/labtether/protocol"
)

// StatfsMountPoint is not supported on this platform; it always returns an error.
// collectMountsLinux is never called on these platforms anyway (only on linux).
func StatfsMountPoint(device, mountPoint, fsType string) (protocol.MountInfo, error) {
	return protocol.MountInfo{}, fmt.Errorf("statfs not supported on this platform")
}
