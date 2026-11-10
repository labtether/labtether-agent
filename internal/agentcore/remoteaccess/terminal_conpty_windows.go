//go:build windows

package remoteaccess

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Pseudo consoles (ConPTY) arrived in Windows 10 1809. golang.org/x/sys panics
// when the procedure is missing, so it is looked up here before any call.
var procCreatePseudoConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole")

// pseudoConsoleAvailable is a variable so a test can take the pipe route.
var pseudoConsoleAvailable = func() bool { return procCreatePseudoConsole.Find() == nil }

// consoleTerminal is a shell attached to a pseudo console. The console gives
// the shell a real terminal: line editing, Ctrl+C, colours, paging and size.
// The job object holds the shell and every program it starts, including ones
// that open their own console, so closing the terminal leaves none behind.
type consoleTerminal struct {
	mu       sync.Mutex
	console  windows.Handle // zero once closed
	job      windows.Handle
	stopOnce sync.Once
}

// startNativeTerminal runs cmd on a pseudo console of the given size. A system
// without pseudo consoles gets the pipe bridge it had before.
func startNativeTerminal(ctx context.Context, cmd *exec.Cmd, cols, rows uint16) (*nativeTerminal, error) {
	if !pseudoConsoleAvailable() {
		return startPipeTerminal(cmd)
	}
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	console, input, output, err := openPseudoConsole(consoleSize(cols, rows))
	if err != nil {
		log.Printf("terminal: pseudo console not created, using pipes: %v", err)
		return startPipeTerminal(cmd)
	}
	term := &consoleTerminal{console: console}
	fail := func(err error) (*nativeTerminal, error) {
		// Pipes first: nothing reads them, and an older console host waits
		// for a reader before it lets its console close.
		_ = input.Close()
		_ = output.Close()
		windows.ClosePseudoConsole(console)
		return nil, err
	}
	if term.job, err = newKillOnCloseJob(); err != nil {
		return fail(fmt.Errorf("create job object: %w", err))
	}
	process, err := startConsoleProcess(cmd, console, term.job)
	if err != nil {
		_ = windows.CloseHandle(term.job)
		return fail(err)
	}

	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		_, _ = windows.WaitForSingleObject(process, windows.INFINITE)
		var code uint32
		exitErr := windows.GetExitCodeProcess(process, &code)
		_ = windows.CloseHandle(process)
		close(exited)
		// Programs the shell left running end with it, and closing the console
		// sends its last output to the reader, followed by end-of-file.
		term.stop()
		if exitErr == nil && code != 0 {
			exitErr = fmt.Errorf("exit status %d", code)
		}
		done <- exitErr
		close(done)
	}()
	go func() {
		select {
		case <-ctx.Done():
			term.stop()
		case <-exited:
		}
	}()
	return &nativeTerminal{input: input, output: output, done: done, resize: term.resize, stop: term.stop}, nil
}

// openPseudoConsole returns the console with the agent's ends of its two
// pipes: input the console reads as keys, and output it writes as UTF-8 text
// with VT sequences.
func openPseudoConsole(size windows.Coord) (console windows.Handle, input, output *os.File, err error) {
	var consoleIn, agentIn, agentOut, consoleOut windows.Handle
	if err = windows.CreatePipe(&consoleIn, &agentIn, nil, 0); err != nil {
		return 0, nil, nil, fmt.Errorf("create console input pipe: %w", err)
	}
	if err = windows.CreatePipe(&agentOut, &consoleOut, nil, 0); err != nil {
		_ = windows.CloseHandle(consoleIn)
		_ = windows.CloseHandle(agentIn)
		return 0, nil, nil, fmt.Errorf("create console output pipe: %w", err)
	}
	err = windows.CreatePseudoConsole(size, consoleIn, consoleOut, 0, &console)
	// The console host keeps its own copies of its pipe ends. The agent's
	// copies must close, or output never reaches end-of-file.
	_ = windows.CloseHandle(consoleIn)
	_ = windows.CloseHandle(consoleOut)
	if err != nil {
		_ = windows.CloseHandle(agentIn)
		_ = windows.CloseHandle(agentOut)
		return 0, nil, nil, fmt.Errorf("create pseudo console: %w", err)
	}
	return console, os.NewFile(uintptr(agentIn), "console-input"), os.NewFile(uintptr(agentOut), "console-output"), nil
}

// consoleSize keeps a requested size inside what a pseudo console accepts.
func consoleSize(cols, rows uint16) windows.Coord {
	clamp := func(value uint16) int16 {
		if value < 1 {
			return 1
		}
		if value > 32767 {
			return 32767
		}
		return int16(value)
	}
	return windows.Coord{X: clamp(cols), Y: clamp(rows)}
}

func (t *consoleTerminal) resize(cols, rows uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.console == 0 {
		return
	}
	_ = windows.ResizePseudoConsole(t.console, consoleSize(cols, rows))
}

// stop ends the shell and every program it started, then closes the console.
// It is safe to call more than once and from any goroutine.
func (t *consoleTerminal) stop() {
	t.stopOnce.Do(func() {
		_ = windows.TerminateJobObject(t.job, 1)
		t.mu.Lock()
		console := t.console
		t.console = 0
		t.mu.Unlock()
		// Before Windows 11 24H2 this call waits until the console's last
		// output has been read, so it must not hold up the caller.
		go windows.ClosePseudoConsole(console)
		_ = windows.CloseHandle(t.job)
	})
}

// newKillOnCloseJob returns a job object that ends its processes when its
// handle closes, which also covers the agent itself dying.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}
