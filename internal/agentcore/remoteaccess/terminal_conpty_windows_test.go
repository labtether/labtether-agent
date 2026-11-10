//go:build windows

package remoteaccess

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/labtether/protocol"
)

// consoleTestHub stands in for the Hub: it keeps what the terminal sends.
type consoleTestHub struct {
	mu      sync.Mutex
	output  []byte
	started int
	closed  []string
}

func (h *consoleTestHub) Send(msg protocol.Message) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch msg.Type {
	case protocol.MsgTerminalStarted:
		h.started++
	case protocol.MsgTerminalData:
		var payload protocol.TerminalDataPayload
		if err := json.Unmarshal(msg.Data, &payload); err == nil {
			if data, err := base64.StdEncoding.DecodeString(payload.Data); err == nil {
				h.output = append(h.output, data...)
			}
		}
	case protocol.MsgTerminalClosed:
		var payload protocol.TerminalCloseData
		_ = json.Unmarshal(msg.Data, &payload)
		h.closed = append(h.closed, payload.Reason)
	}
	return nil
}

var vtSequence = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b\[[0-9;?<=>]*[ -/]*[@-~]|\x1b[=>78]`)

// consoleTestTerminal is one cmd.exe session driven through the same
// messages the Hub sends.
type consoleTestTerminal struct {
	t       *testing.T
	manager *TerminalManager
	hub     *consoleTestHub
	id      string
	mark    int
}

func startConsoleTestTerminal(t *testing.T, cols, rows int) *consoleTestTerminal {
	t.Helper()
	term := &consoleTestTerminal{t: t, manager: NewTerminalManager(), hub: &consoleTestHub{}, id: "console-" + t.Name()}
	t.Cleanup(term.manager.CloseAll)
	raw, _ := json.Marshal(protocol.TerminalStartData{SessionID: term.id, Shell: "cmd.exe", Cols: cols, Rows: rows})
	term.manager.HandleTerminalStart(term.hub, protocol.Message{Data: raw})
	term.hub.mu.Lock()
	started, closed := term.hub.started, append([]string(nil), term.hub.closed...)
	term.hub.mu.Unlock()
	if started != 1 {
		t.Fatalf("terminal did not start: closed=%v", closed)
	}
	term.waitFor("the first prompt", `>`)
	return term
}

// send types text into the terminal, as keys from the Hub.
func (c *consoleTestTerminal) send(text string) {
	c.t.Helper()
	c.hub.mu.Lock()
	c.mark = len(c.hub.output)
	c.hub.mu.Unlock()
	raw, _ := json.Marshal(protocol.TerminalDataPayload{SessionID: c.id, Data: base64.StdEncoding.EncodeToString([]byte(text))})
	c.manager.HandleTerminalData(protocol.Message{Data: raw})
}

// screen is the output since the last send, without VT sequences.
func (c *consoleTestTerminal) screen() string {
	c.hub.mu.Lock()
	defer c.hub.mu.Unlock()
	return vtSequence.ReplaceAllString(string(c.hub.output[c.mark:]), "")
}

func (c *consoleTestTerminal) waitFor(what, pattern string) {
	c.t.Helper()
	want := regexp.MustCompile(pattern)
	deadline := time.Now().Add(20 * time.Second)
	for !want.MatchString(c.screen()) {
		if time.Now().After(deadline) {
			c.t.Fatalf("%s never showed; output since the last keys: %q", what, c.screen())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (c *consoleTestTerminal) closedReasons() []string {
	c.hub.mu.Lock()
	defer c.hub.mu.Unlock()
	return append([]string(nil), c.hub.closed...)
}

// Fault: on pipes Backspace stayed in the command as a DEL byte, so a
// corrected line still ran the mistake. Also guards non-ASCII text against
// the console code page, and that a typed exit closes the session at once.
func TestConsoleTerminalEditsLineKeepsUnicodeAndExits(t *testing.T) {
	term := startConsoleTestTerminal(t, 100, 30)

	term.send("set /a 111111*8\x7f7\r")
	term.waitFor("the result of the corrected line", `777777`)

	term.send("set V=é✓\r")
	term.send("echo [%V%%V%]\r")
	term.waitFor("non-ASCII output", `\[é✓é✓\]`)

	term.send("exit\r")
	deadline := time.Now().Add(5 * time.Second)
	for len(term.closedReasons()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("typed exit did not close the session")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if reasons := term.closedReasons(); len(reasons) != 1 || reasons[0] != "shell exited" {
		t.Fatalf("closed reasons = %q, want one \"shell exited\"", reasons)
	}
	term.manager.Mu.Lock()
	left := len(term.manager.Sessions)
	term.manager.Mu.Unlock()
	if left != 0 {
		t.Fatalf("%d sessions left after exit", left)
	}
}

// Fault: the shell kept its first size whatever the browser pane was, so
// wide output wrapped and full-screen programs drew wrongly.
func TestConsoleTerminalStartsAtAndFollowsRequestedSize(t *testing.T) {
	term := startConsoleTestTerminal(t, 91, 27)
	term.send("mode con\r")
	term.waitFor("the start size", `Lines:\s*27[^0-9][\s\S]*olumns:\s*91[^0-9]`)

	raw, _ := json.Marshal(protocol.TerminalResizeData{SessionID: term.id, Cols: 97, Rows: 31})
	term.manager.HandleTerminalResize(protocol.Message{Data: raw})
	term.send("mode con\r")
	term.waitFor("the new size", `Lines:\s*31[^0-9][\s\S]*olumns:\s*97[^0-9]`)
}

// Fault: Ctrl+C arrived as a plain byte, so a running program never stopped
// and the shell was lost. The agent itself is made to ignore Ctrl+C first, as
// it does when started in a new process group: the shell must not inherit
// that, and the agent must keep its own setting.
func TestConsoleTerminalCtrlCStopsRunningProgram(t *testing.T) {
	parameters := windows.RtlGetCurrentPeb().ProcessParameters
	ignoredBefore := parameters.ConsoleFlags&consoleIgnoreCtrlC != 0
	setIgnoreCtrlC(true)
	t.Cleanup(func() { setIgnoreCtrlC(ignoredBefore) })

	term := startConsoleTestTerminal(t, 100, 30)
	if parameters.ConsoleFlags&consoleIgnoreCtrlC == 0 {
		t.Fatal("starting a terminal changed the agent's own Ctrl+C setting")
	}
	term.send("ping -t 127.0.0.1\r")
	term.waitFor("ping replies", `bytes=32`)
	pings := childProcesses(t, shellProcess(t), "PING.EXE")
	if len(pings) != 1 {
		t.Fatalf("found %d ping processes, want 1", len(pings))
	}

	term.send("\x03")
	waitForExit(t, "ping after Ctrl+C", pings[0])
	term.send("set /a 111111*7\r")
	term.waitFor("the shell to take the next command", `777777`)
}

// Fault: closing the tab killed the shell only, and "ping -t" ran on with no
// parent. One ping here stays on the terminal; the other opens its own
// console, which closing the pseudo console alone does not reach.
func TestConsoleTerminalCloseEndsEverythingItStarted(t *testing.T) {
	term := startConsoleTestTerminal(t, 100, 30)
	shell := shellProcess(t)
	term.send("start \"\" /min ping -t 127.0.0.1\r")
	term.waitFor("the prompt after start", `>`)
	term.send("ping -t 127.0.0.1\r")
	term.waitFor("ping replies", `bytes=32`)
	pings := childProcesses(t, shell, "PING.EXE")
	if len(pings) != 2 {
		t.Fatalf("found %d ping processes, want 2", len(pings))
	}

	raw, _ := json.Marshal(protocol.TerminalCloseData{SessionID: term.id})
	term.manager.HandleTerminalClose(protocol.Message{Data: raw})
	for _, ping := range pings {
		waitForExit(t, "ping after the session closed", ping)
	}
}

// Guards the route for Windows before 10 1809, which has no pseudo console:
// the shell must still start and run a command over pipes.
func TestConsoleTerminalUsesPipesWithoutPseudoConsole(t *testing.T) {
	available := pseudoConsoleAvailable
	pseudoConsoleAvailable = func() bool { return false }
	t.Cleanup(func() { pseudoConsoleAvailable = available })

	term := startConsoleTestTerminal(t, 100, 30)
	term.manager.Mu.Lock()
	sess := term.manager.Sessions[term.id]
	term.manager.Mu.Unlock()
	if sess == nil || sess.resize != nil || sess.stop != nil {
		t.Fatal("session did not take the pipe route")
	}
	term.send("set /a 111111*7\r\n")
	term.waitFor("the result over pipes", `777777`)
}

// shellProcess returns the id of the one cmd.exe this test process started.
func shellProcess(t *testing.T) uint32 {
	t.Helper()
	var shells []uint32
	eachProcess(t, func(entry *windows.ProcessEntry32) {
		if entry.ParentProcessID == uint32(os.Getpid()) && strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "cmd.exe") {
			shells = append(shells, entry.ProcessID)
		}
	})
	if len(shells) != 1 {
		t.Fatalf("found %d shells started by this test, want 1", len(shells))
	}
	return shells[0]
}

// childProcesses opens every child of parent with the given image name.
// A held handle keeps the process id from being reused before the check, and
// lets a failed test end what it started.
func childProcesses(t *testing.T, parent uint32, image string) []windows.Handle {
	t.Helper()
	var handles []windows.Handle
	eachProcess(t, func(entry *windows.ProcessEntry32) {
		if entry.ParentProcessID != parent || !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), image) {
			return
		}
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, entry.ProcessID)
		if err != nil {
			t.Fatalf("open %s %d: %v", image, entry.ProcessID, err)
		}
		handles = append(handles, handle)
		t.Cleanup(func() {
			_ = windows.TerminateProcess(handle, 1)
			_ = windows.CloseHandle(handle)
		})
	})
	return handles
}

func eachProcess(t *testing.T, visit func(*windows.ProcessEntry32)) {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatalf("list processes: %v", err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		visit(&entry)
	}
}

func waitForExit(t *testing.T, what string, process windows.Handle) {
	t.Helper()
	event, err := windows.WaitForSingleObject(process, 10000)
	if err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("%s is still running (wait result %#x, %v)", what, event, err)
	}
}
