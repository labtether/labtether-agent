//go:build linux || darwin

package system

import (
	"syscall"

	"github.com/labtether/protocol"
)

// StatfsMountPoint uses syscall.Statfs to collect disk space info for a mount point.
func StatfsMountPoint(device, mountPoint, fsType string) (protocol.MountInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &stat); err != nil {
		return protocol.MountInfo{}, err
	}

	blockSize := uint64(0)
	if stat.Bsize > 0 {
		blockSize = uint64(stat.Bsize)
	}

	total := saturatingBlockBytes(uint64(stat.Blocks), blockSize)
	available := saturatingBlockBytes(uint64(stat.Bavail), blockSize)
	free := saturatingBlockBytes(uint64(stat.Bfree), blockSize)
	used := uint64(0)
	if total > free {
		used = total - free
	}

	var usePct float64
	if total > 0 {
		usePct = float64(used) / float64(total) * 100
	}

	return protocol.MountInfo{
		Device:     device,
		MountPoint: mountPoint,
		FSType:     fsType,
		Total:      total,
		Used:       used,
		Available:  available,
		UsePct:     usePct,
	}, nil
}

func saturatingBlockBytes(blocks, blockSize uint64) uint64 {
	if blocks == 0 || blockSize == 0 {
		return 0
	}
	maxUint64 := ^uint64(0)
	if blocks > maxUint64/blockSize {
		return maxUint64
	}
	return blocks * blockSize
}
