//go:build !windows

package remoteaccess

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// tmuxHarness runs a TerminalManager against a private tmux server and plays
// the Hub: it starts terminals, types into them and collects what they send.
type tmuxHarness struct {
	t        *testing.T
	tmuxPath string
	env      []string
	home     string
	manager  *TerminalManager
	next     int

	mu      sync.Mutex
	output  map[string][]byte
	started map[string]bool
	closed  map[string]string
}

func newTmuxHarness(t *testing.T) *tmuxHarness {
	t.Helper()
	tmuxPath, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux is not installed")
	}
	if version, _ := exec.Command(tmuxPath, "-V").Output(); !tmuxSupportsControl(string(version)) {
		t.Skipf("%s has no usable control mode", strings.TrimSpace(string(version)))
	}
	// A short socket folder: unix socket paths have a small length limit.
	sockDir, err := os.MkdirTemp("/tmp", "lt-tmux-")
	if err != nil {
		t.Fatal(err)
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The shell starts in the home folder; keep that inside the test.
	t.Setenv("HOME", home)
	h := &tmuxHarness{
		t:        t,
		tmuxPath: tmuxPath,
		home:     home,
		env:      []string{"TMUX_TMPDIR=" + sockDir, "SHELL=/bin/sh", "ENV=", "PS1=ready$ "},
		manager:  NewTerminalManager(),
		output:   map[string][]byte{},
		started:  map[string]bool{},
		closed:   map[string]string{},
	}
	h.manager.tmuxEnv = h.env
	t.Cleanup(func() {
		h.manager.CloseAll()
		h.tmux("kill-server")
		_ = os.RemoveAll(sockDir)
	})
	return h
}

func (h *tmuxHarness) Send(msg protocol.Message) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch msg.Type {
	case protocol.MsgTerminalStarted:
		h.started[msg.ID] = true
	case protocol.MsgTerminalData:
		var payload protocol.TerminalDataPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			return err
		}
		data, err := base64.StdEncoding.DecodeString(payload.Data)
		if err != nil {
			return err
		}
		h.output[payload.SessionID] = append(h.output[payload.SessionID], data...)
	case protocol.MsgTerminalClosed:
		var payload protocol.TerminalCloseData
		_ = json.Unmarshal(msg.Data, &payload)
		h.closed[msg.ID] = firstNonEmpty(payload.Reason, "closed")
	}
	return nil
}

// tmux runs a tmux command on the private server.
func (h *tmuxHarness) tmux(args ...string) string {
	cmd := exec.Command(h.tmuxPath, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + h.home, "TERM=xterm-256color"}, h.env...)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

// open starts a terminal on the named tmux session and waits until the agent
// reports it started. It returns the terminal's ID.
func (h *tmuxHarness) open(session string, cols, rows int) string {
	h.t.Helper()
	h.next++
	id := fmt.Sprintf("stream-%d", h.next)
	raw, _ := json.Marshal(protocol.TerminalStartData{SessionID: id, Cols: cols, Rows: rows, UseTmux: true, TmuxSession: session})
	h.manager.HandleTerminalStart(h, protocol.Message{Data: raw})
	h.mu.Lock()
	started, reason := h.started[id], h.closed[id]
	h.mu.Unlock()
	if !started {
		h.t.Fatalf("terminal did not start: %q", reason)
	}
	h.manager.Mu.Lock()
	sess := h.manager.Sessions[id]
	h.manager.Mu.Unlock()
	if sess == nil || sess.Ptmx != nil {
		h.t.Fatal("terminal did not use tmux control mode")
	}
	return id
}

func (h *tmuxHarness) typeBytes(id string, data []byte) {
	raw, _ := json.Marshal(protocol.TerminalDataPayload{SessionID: id, Data: base64.StdEncoding.EncodeToString(data)})
	h.manager.HandleTerminalData(protocol.Message{Data: raw})
}

func (h *tmuxHarness) typeLine(id, line string) { h.typeBytes(id, []byte(line+"\n")) }

func (h *tmuxHarness) resize(id string, cols, rows int) {
	raw, _ := json.Marshal(protocol.TerminalResizeData{SessionID: id, Cols: cols, Rows: rows})
	h.manager.HandleTerminalResize(protocol.Message{Data: raw})
}

// detach closes the stream the way the Hub does when a tab closes.
func (h *tmuxHarness) detach(id string) {
	h.t.Helper()
	raw, _ := json.Marshal(protocol.TerminalCloseData{SessionID: id})
	h.manager.HandleTerminalClose(protocol.Message{Data: raw})
	h.waitClosed(id)
}

func (h *tmuxHarness) seen(id string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]byte{}, h.output[id]...)
}

func (h *tmuxHarness) waitClosed(id string) string {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		h.mu.Lock()
		reason := h.closed[id]
		h.mu.Unlock()
		if reason != "" {
			return reason
		}
		if time.Now().After(deadline) {
			h.t.Fatal("terminal was not reported closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitOutput waits until the terminal's output contains want and returns all
// of it so far.
func (h *tmuxHarness) waitOutput(id, want string, timeout time.Duration) []byte {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		seen := h.seen(id)
		if bytes.Contains(seen, []byte(want)) {
			return seen
		}
		if time.Now().After(deadline) {
			tail := seen
			if len(tail) > 400 {
				tail = tail[len(tail)-400:]
			}
			h.t.Fatalf("no %q in terminal output; %d bytes, ending %q", want, len(seen), tail)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitTmux waits until a tmux format for the session's pane reads want.
func (h *tmuxHarness) waitTmux(session, format, want string, timeout time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := h.tmux("display-message", "-p", "-t", "="+session+":", format)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("tmux %s is %q, want %q", format, got, want)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// ready waits for the shell to answer, so that typed text is not lost in its
// start-up.
func (h *tmuxHarness) ready(id string) {
	h.t.Helper()
	h.typeLine(id, "echo shell-$((1+1))-up")
	h.waitOutput(id, "shell-2-up", 15*time.Second)
}

var terminalControlSequence = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[c=>]|\x1b\)0|[\x0f\x18]`)

// plainLines removes control sequences and returns the lines a terminal
// would hold, in the order written.
func plainLines(output []byte) []string {
	text := terminalControlSequence.ReplaceAll(output, nil)
	return strings.Split(strings.ReplaceAll(string(text), "\r", ""), "\n")
}
