package system

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// CollectMountsFn is the function used to collect mount information.
// It can be overridden in tests.
var CollectMountsFn = CollectMounts

// DiskManager handles disk/mount info requests from the hub.
// It carries no persistent state; the struct exists for consistency
// with the other manager types.
type DiskManager struct{}

// NewDiskManager creates a new DiskManager.
func NewDiskManager() *DiskManager { return &DiskManager{} }

// CloseAll is a no-op for DiskManager -- disk requests are stateless
// and require no cleanup.
func (dm *DiskManager) CloseAll() {}

// HandleDiskList collects mount/disk info and sends it to the hub.
func (dm *DiskManager) HandleDiskList(transport MessageSender, msg protocol.Message) {
	var req protocol.DiskListData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("disk: invalid disk.list request: %v", err)
		return
	}

	mounts, err := CollectMountsFn()

	var errMsg string
	if err != nil {
		errMsg = err.Error()
		log.Printf("disk: failed to collect mounts: %v", err)
	}

	data, marshalErr := json.Marshal(protocol.DiskListedData{
		RequestID: req.RequestID,
		Mounts:    mounts,
		Error:     errMsg,
	})
	if marshalErr != nil {
		log.Printf("disk: failed to marshal disk.listed response: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgDiskListed,
		ID:   req.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("disk: failed to send disk.listed for request %s: %v", req.RequestID, sendErr)
	}
}

// VirtualFSTypes is the set of filesystem types to skip when collecting mounts.
var VirtualFSTypes = map[string]bool{
	"proc":        true,
	"sysfs":       true,
	"devtmpfs":    true,
	"tmpfs":       true,
	"devpts":      true,
	"securityfs":  true,
	"cgroup":      true,
	"cgroup2":     true,
	"pstore":      true,
	"debugfs":     true,
	"tracefs":     true,
	"hugetlbfs":   true,
	"mqueue":      true,
	"binfmt_misc": true,
	"autofs":      true,
	"configfs":    true,
	"efivarfs":    true,
	"fusectl":     true,
	"fuse.lnk":    true,
}

// CollectMounts collects mount/disk information from the system.
// On Linux it reads /proc/mounts and uses syscall.Statfs for space info.
// On macOS and other platforms it parses `df -k` output.
func CollectMounts() ([]protocol.MountInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return collectMountsLinux()
	case "windows":
		return collectMountsWindows()
	default:
		return collectMountsDF()
	}
}

// collectMountsLinux reads /proc/mounts and calls StatfsMountPoint for each
// real filesystem entry.
func collectMountsLinux() ([]protocol.MountInfo, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		// Fall back to df -k if /proc/mounts is unavailable.
		return collectMountsDF()
	}

	var mounts []protocol.MountInfo
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// /proc/mounts format: device mountpoint fstype options dump pass
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip virtual filesystems.
		if VirtualFSTypes[fsType] {
			continue
		}
		// Skip none device or virtual paths.
		if device == "none" {
			continue
		}
		if strings.HasPrefix(mountPoint, "/sys") || strings.HasPrefix(mountPoint, "/proc") {
			continue
		}
		// Skip Docker overlay mounts.
		if fsType == "overlay" && strings.HasPrefix(mountPoint, "/var/lib/docker") {
			continue
		}

		info, statErr := StatfsMountPoint(device, mountPoint, fsType)
		if statErr != nil {
			securityruntime.Logf("disk: statfs %s: %v", mountPoint, statErr)
			continue
		}
		mounts = append(mounts, info)
	}
	return mounts, nil
}

// collectMountsDF parses POSIX `df -kP` output to collect mount/disk information.
// This works on Linux, macOS, and FreeBSD.
//
// df -kP column layout:
//
//	Filesystem  1024-blocks  Used  Available  Use%  Mounted on
//	0           1            2     3          4     5
func collectMountsDF() ([]protocol.MountInfo, error) {
	out, err := securityruntime.CaptureCombinedOutput(
		exec.Command("df", "-kP"),
		securityruntime.DefaultCommandOutputLimit,
	)
	if err != nil {
		return nil, err
	}
	return parseMountsDFOutput(string(out)), nil
}

// parseMountsDFOutput locates the numeric df columns instead of assuming the
// filesystem name is one token. This also accepts the extended Darwin `df -k`
// layout, which inserts iused/ifree/%iused before the mount point.
func parseMountsDFOutput(out string) []protocol.MountInfo {
	var mounts []protocol.MountInfo
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Skip the header line.
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		columnStart := findDFNumericColumns(fields)
		if columnStart < 1 {
			continue
		}
		mountPointStart := columnStart + 4
		// Darwin's non-POSIX df output includes inode counts after Capacity:
		// iused ifree %iused. Accept that layout defensively as well.
		if len(fields) >= mountPointStart+4 &&
			isDFUint(fields[mountPointStart]) &&
			isDFUint(fields[mountPointStart+1]) &&
			isDFPercent(fields[mountPointStart+2]) {
			mountPointStart += 3
		}
		if mountPointStart >= len(fields) {
			continue
		}

		device := strings.Join(fields[:columnStart], " ")
		mountPoint := strings.Join(fields[mountPointStart:], " ")

		// Skip virtual paths.
		if strings.HasPrefix(mountPoint, "/sys") || strings.HasPrefix(mountPoint, "/proc") {
			continue
		}
		// Skip obvious virtual devices.
		if device == "none" || device == "tmpfs" || device == "devtmpfs" || device == "devfs" {
			continue
		}

		totalKB, totalErr := strconv.ParseUint(fields[columnStart], 10, 64)
		usedKB, usedErr := strconv.ParseUint(fields[columnStart+1], 10, 64)
		availKB, availErr := strconv.ParseUint(fields[columnStart+2], 10, 64)
		if totalErr != nil || usedErr != nil || availErr != nil || totalKB == 0 {
			continue
		}

		total := totalKB * 1024
		used := usedKB * 1024
		available := availKB * 1024

		usePct, percentErr := strconv.ParseFloat(strings.TrimSuffix(fields[columnStart+3], "%"), 64)
		if percentErr != nil {
			usePct = float64(used) / float64(total) * 100
		}

		mounts = append(mounts, protocol.MountInfo{
			Device:     device,
			MountPoint: mountPoint,
			FSType:     "", // df -k does not include fstype by default
			Total:      total,
			Used:       used,
			Available:  available,
			UsePct:     usePct,
		})
	}
	return mounts
}

func findDFNumericColumns(fields []string) int {
	for i := 1; i+3 < len(fields); i++ {
		if isDFUint(fields[i]) && isDFUint(fields[i+1]) && isDFUint(fields[i+2]) && isDFPercent(fields[i+3]) {
			return i
		}
	}
	return -1
}

func isDFUint(value string) bool {
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func isDFPercent(value string) bool {
	if !strings.HasSuffix(value, "%") {
		return false
	}
	_, err := strconv.ParseFloat(strings.TrimSuffix(value, "%"), 64)
	return err == nil
}
