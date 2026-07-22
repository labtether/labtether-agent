//go:build windows

package system

import (
	"errors"
	"runtime"
	"time"
	"unsafe"

	"github.com/labtether/protocol"
	"golang.org/x/sys/windows"
)

var (
	psapiDLL                 = windows.NewLazySystemDLL("psapi.dll")
	getProcessMemoryInfoProc = psapiDLL.NewProc("GetProcessMemoryInfo")
	kernel32DLL              = windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusExProc = kernel32DLL.NewProc("GlobalMemoryStatusEx")
)

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS_EX. The uintptr fields
// match SIZE_T on both 32-bit and 64-bit Windows.
type processMemoryCounters struct {
	Size                       uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// memoryStatusEx mirrors MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length            uint32
	MemoryLoad        uint32
	TotalPhysical     uint64
	AvailablePhysical uint64
	TotalPageFile     uint64
	AvailablePageFile uint64
	TotalVirtual      uint64
	AvailableVirtual  uint64
	AvailableExtended uint64
}

// CollectProcesses enumerates processes through the Windows Tool Help API.
// Per-process details can be unavailable for protected processes; those entries
// are still returned with the information Windows exposes through the snapshot.
func CollectProcesses() ([]protocol.ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	totalPhysical := windowsTotalPhysicalMemory()
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}

	processes := make([]protocol.ProcessInfo, 0, 128)
	for {
		processes = append(processes, windowsProcessInfo(&entry, totalPhysical))

		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return processes, err
		}
	}

	return processes, nil
}

func windowsProcessInfo(entry *windows.ProcessEntry32, totalPhysical uint64) protocol.ProcessInfo {
	name := windows.UTF16ToString(entry.ExeFile[:])
	info := protocol.ProcessInfo{
		PID:     int(entry.ProcessID),
		Name:    name,
		Command: name,
	}

	handle, err := openProcessForInspection(entry.ProcessID)
	if err != nil {
		return info
	}
	defer windows.CloseHandle(handle)

	if command, err := windowsProcessImagePath(handle); err == nil && command != "" {
		info.Command = command
	}
	info.User = windowsProcessUser(handle)
	info.MemRSS = windowsProcessRSSKB(handle)
	if totalPhysical > 0 && info.MemRSS > 0 {
		info.MemPct = float64(uint64(info.MemRSS)*1024) / float64(totalPhysical) * 100
	}
	info.CPUPct = windowsAverageCPUPercent(handle)

	return info
}

func openProcessForInspection(pid uint32) (windows.Handle, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false,
		pid,
	)
	if err == nil {
		return handle, nil
	}

	// Protected processes can deny VM_READ while still allowing their image,
	// owner, and CPU time to be queried.
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
}

func windowsProcessImagePath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 1024)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func windowsProcessUser(handle windows.Handle) string {
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil || tokenUser == nil || tokenUser.User.Sid == nil {
		return ""
	}
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return tokenUser.User.Sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

func windowsProcessRSSKB(handle windows.Handle) int64 {
	counters := processMemoryCounters{Size: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	result, _, _ := getProcessMemoryInfoProc.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.Size),
	)
	if result == 0 {
		return 0
	}
	return int64(counters.WorkingSetSize / 1024)
}

func windowsAverageCPUPercent(handle windows.Handle) float64 {
	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime); err != nil {
		return 0
	}

	createdAt := time.Unix(0, creationTime.Nanoseconds())
	elapsed := time.Since(createdAt)
	if elapsed <= 0 {
		return 0
	}
	cpuTicks := filetimeTicks(kernelTime) + filetimeTicks(userTime)
	cpuDuration := time.Duration(cpuTicks * 100)
	percent := float64(cpuDuration) / float64(elapsed) * 100 / float64(runtime.NumCPU())
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func filetimeTicks(value windows.Filetime) uint64 {
	return uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime)
}

func windowsTotalPhysicalMemory() uint64 {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	result, _, _ := globalMemoryStatusExProc.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		return 0
	}
	return status.TotalPhysical
}
