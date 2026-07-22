//go:build windows

package system

import (
	"errors"
	"fmt"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
	"golang.org/x/sys/windows"
)

// collectMountsWindows enumerates Windows drive-letter roots through native
// Win32 APIs. Remote drive mappings are reported without probing their capacity
// so an unavailable network server cannot stall the agent inventory request.
func collectMountsWindows() ([]protocol.MountInfo, error) {
	drives, err := windowsLogicalDrives()
	if err != nil {
		return nil, err
	}

	mounts := make([]protocol.MountInfo, 0, len(drives))
	var probeErrors []error
	for _, root := range drives {
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil {
			probeErrors = append(probeErrors, fmt.Errorf("drive %q: %w", root, err))
			continue
		}

		driveType := windows.GetDriveType(rootPtr)
		if driveType == windows.DRIVE_UNKNOWN || driveType == windows.DRIVE_NO_ROOT_DIR {
			continue
		}
		if driveType == windows.DRIVE_REMOTE {
			mounts = append(mounts, protocol.MountInfo{
				Device:     root,
				MountPoint: root,
				FSType:     "remote",
			})
			continue
		}

		info, err := windowsMountInfo(root, rootPtr)
		if err != nil {
			// Empty optical/removable drives commonly fail capacity queries. Keep
			// useful fixed-volume results and only fail the request if none work.
			probeErrors = append(probeErrors, fmt.Errorf("drive %s: %w", root, err))
			securityruntime.Logf("disk: Windows volume probe %s: %v", root, err)
			continue
		}
		mounts = append(mounts, info)
	}

	if len(mounts) == 0 && len(probeErrors) > 0 {
		return nil, fmt.Errorf("failed to inspect Windows volumes: %w", errors.Join(probeErrors...))
	}
	return mounts, nil
}

func windowsLogicalDrives() ([]string, error) {
	buffer := make([]uint16, 256)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buffer)), &buffer[0])
	if err != nil {
		return nil, fmt.Errorf("GetLogicalDriveStrings: %w", err)
	}
	if n > uint32(len(buffer)) {
		buffer = make([]uint16, n+1)
		n, err = windows.GetLogicalDriveStrings(uint32(len(buffer)), &buffer[0])
		if err != nil {
			return nil, fmt.Errorf("GetLogicalDriveStrings: %w", err)
		}
	}
	if n > uint32(len(buffer)) {
		return nil, errors.New("GetLogicalDriveStrings returned an oversized result")
	}
	return parseWindowsDriveMultiString(buffer[:n]), nil
}

func parseWindowsDriveMultiString(buffer []uint16) []string {
	var drives []string
	for start := 0; start < len(buffer); {
		end := start
		for end < len(buffer) && buffer[end] != 0 {
			end++
		}
		if end == start {
			break
		}
		if drive := strings.TrimSpace(windows.UTF16ToString(buffer[start:end])); drive != "" {
			drives = append(drives, drive)
		}
		start = end + 1
	}
	return drives
}

func windowsMountInfo(root string, rootPtr *uint16) (protocol.MountInfo, error) {
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(rootPtr, &available, &total, &free); err != nil {
		return protocol.MountInfo{}, fmt.Errorf("GetDiskFreeSpaceEx: %w", err)
	}
	if total == 0 || free > total {
		return protocol.MountInfo{}, fmt.Errorf("invalid capacity total=%d free=%d", total, free)
	}

	fsBuffer := make([]uint16, 64)
	fsType := ""
	if err := windows.GetVolumeInformation(rootPtr, nil, 0, nil, nil, nil, &fsBuffer[0], uint32(len(fsBuffer))); err == nil {
		fsType = strings.TrimSpace(windows.UTF16ToString(fsBuffer))
	}

	used := total - free
	return protocol.MountInfo{
		Device:     root,
		MountPoint: root,
		FSType:     fsType,
		Total:      total,
		Used:       used,
		Available:  available,
		UsePct:     float64(used) / float64(total) * 100,
	}, nil
}
