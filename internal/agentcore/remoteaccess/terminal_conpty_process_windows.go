//go:build windows

package remoteaccess

import (
	"fmt"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startConsoleProcess starts cmd attached to the pseudo console and inside
// the job. os/exec cannot attach a pseudo console, so the process is created
// directly from the command's resolved path, arguments, environment and
// folder. It starts suspended and joins the job before its first instruction,
// so nothing it starts can be outside the job. The caller owns the returned
// process handle.
func startConsoleProcess(cmd *exec.Cmd, console, job windows.Handle) (windows.Handle, error) {
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, fmt.Errorf("create process attribute list: %w", err)
	}
	defer attributes.Delete()
	// This attribute takes the console handle itself as its value, not a
	// pointer to it.
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		handleAsPointer(console), unsafe.Sizeof(console)); err != nil {
		return 0, fmt.Errorf("attach pseudo console: %w", err)
	}

	startup := windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	// With no standard handles named, the shell takes the console's. Without
	// this flag it can take the agent's own redirected handles when the agent
	// runs under a service or an SSH session.
	startup.Flags = windows.STARTF_USESTDHANDLES

	application, err := windows.UTF16PtrFromString(cmd.Path)
	if err != nil {
		return 0, fmt.Errorf("shell path: %w", err)
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(cmd.Args))
	if err != nil {
		return 0, fmt.Errorf("shell arguments: %w", err)
	}
	environment, err := environmentBlock(cmd.Environ())
	if err != nil {
		return 0, err
	}
	var folder *uint16
	if cmd.Dir != "" {
		if folder, err = windows.UTF16PtrFromString(cmd.Dir); err != nil {
			return 0, fmt.Errorf("start folder: %w", err)
		}
	}

	var created windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := withCtrlCInherited(func() error {
		return windows.CreateProcess(application, commandLine, nil, nil, false, flags,
			environment, folder, &startup.StartupInfo, &created)
	}); err != nil {
		return 0, err
	}
	defer windows.CloseHandle(created.Thread)
	abandon := func(err error) (windows.Handle, error) {
		_ = windows.TerminateProcess(created.Process, 1)
		_ = windows.CloseHandle(created.Process)
		return 0, err
	}
	if err := windows.AssignProcessToJobObject(job, created.Process); err != nil {
		return abandon(fmt.Errorf("add shell to job object: %w", err))
	}
	if _, err := windows.ResumeThread(created.Thread); err != nil {
		return abandon(fmt.Errorf("resume shell: %w", err))
	}
	return created.Process, nil
}

var (
	procSetConsoleCtrlHandler = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
	ctrlCSettingMu            sync.Mutex
)

// consoleIgnoreCtrlC is the process setting SetConsoleCtrlHandler(NULL, TRUE)
// turns on. Windows copies it to every program the process starts.
const consoleIgnoreCtrlC = 0x1

// withCtrlCInherited runs create with the agent's own "ignore Ctrl+C" setting
// off, then puts it back. An agent started in a new process group has the
// setting on, and so can one started from a script over SSH; a shell that
// inherited it could never interrupt a running program.
func withCtrlCInherited(create func() error) error {
	ctrlCSettingMu.Lock()
	defer ctrlCSettingMu.Unlock()
	parameters := windows.RtlGetCurrentPeb().ProcessParameters
	if parameters == nil || parameters.ConsoleFlags&consoleIgnoreCtrlC == 0 {
		return create()
	}
	setIgnoreCtrlC(false)
	defer setIgnoreCtrlC(true)
	return create()
}

func setIgnoreCtrlC(ignore bool) {
	var add uintptr
	if ignore {
		add = 1
	}
	_, _, _ = procSetConsoleCtrlHandler.Call(0, add)
}

// handleAsPointer passes a handle to an API that takes it in a pointer
// argument. The value is not Go memory, so the collector leaves it alone.
func handleAsPointer(handle windows.Handle) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&handle))
}

// environmentBlock encodes KEY=value entries as CreateProcess wants them:
// UTF-16 strings, each ending in a zero, with one more zero after the last.
func environmentBlock(entries []string) (*uint16, error) {
	block := make([]uint16, 0, 2048)
	for _, entry := range entries {
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("environment entry: %w", err)
		}
		block = append(block, encoded...)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	block = append(block, 0)
	return &block[0], nil
}
