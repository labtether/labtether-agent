package remoteaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// TerminalSession tracks an active PTY shell session on the agent.
type TerminalSession struct {
	sessionID   string
	Ptmx        *os.File
	input       io.WriteCloser
	inputWriter *streaminput.Writer
	output      io.ReadCloser
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	done        chan struct{}
	outputDone  chan struct{}
	closeOnce   sync.Once
}

const MaxTerminalSessions = 10

// A background child may keep the PTY or pipe open after the shell exits.
const terminalOutputDrainTimeout = 2 * time.Second

// TerminalManager manages PTY sessions on the agent.
type TerminalManager struct {
	Mu       sync.Mutex
	Sessions map[string]*TerminalSession
	pending  map[string]*pendingTerminalStart
	startPTY func(*exec.Cmd, *pty.Winsize) (*os.File, error)
}

func NewTerminalManager() *TerminalManager {
	return &TerminalManager{
		Sessions: make(map[string]*TerminalSession),
	}
}

// HandleTerminalProbe checks if tmux is available on this agent and reports back.
func (tm *TerminalManager) HandleTerminalProbe(transport MessageSender) {
	tmuxPath, err := exec.LookPath("tmux")
	hasTmux := err == nil && tmuxPath != ""
	resp := protocol.TerminalProbeResponse{
		HasTmux:  hasTmux,
		TmuxPath: tmuxPath,
	}
	payload, _ := json.Marshal(resp)
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgTerminalProbed,
		Data: payload,
	})
}

// HandleTerminalData writes incoming data to the PTY stdin.
func (tm *TerminalManager) HandleTerminalData(msg protocol.Message) {
	var payload protocol.TerminalDataPayload
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return
	}

	tm.Mu.Lock()
	sess, ok := tm.Sessions[payload.SessionID]
	tm.Mu.Unlock()
	if !ok {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return
	}

	if sess.inputWriter != nil {
		_ = sess.inputWriter.Enqueue(decoded)
	}
}

// HandleTerminalResize changes the PTY window size.
func (tm *TerminalManager) HandleTerminalResize(msg protocol.Message) {
	var req protocol.TerminalResizeData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return
	}

	tm.Mu.Lock()
	sess, ok := tm.Sessions[req.SessionID]
	tm.Mu.Unlock()
	if !ok {
		return
	}

	if sess.Ptmx != nil && req.Cols > 0 && req.Rows > 0 {
		_ = pty.Setsize(sess.Ptmx, &pty.Winsize{
			Cols: ClampUint16(req.Cols),
			Rows: ClampUint16(req.Rows),
		})
	}
}

func ClampUint16(value int) uint16 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(value)
}

// HandleTerminalClose terminates a terminal session.
func (tm *TerminalManager) HandleTerminalClose(msg protocol.Message) {
	var req protocol.TerminalCloseData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return
	}

	tm.Mu.Lock()
	if pending := tm.pending[req.SessionID]; pending != nil {
		pending.cancel()
		delete(tm.pending, req.SessionID)
	}
	sess, ok := tm.Sessions[req.SessionID]
	tm.Mu.Unlock()
	if !ok {
		return
	}

	// Close terminal I/O — this will cause the shell process to exit.
	sess.close()
	if sess.cmd != nil && sess.cmd.Process != nil {
		_ = sess.cmd.Process.Kill()
	}
}

func (tm *TerminalManager) HandleTerminalTmuxKill(transport MessageSender, msg protocol.Message) {
	var req protocol.TerminalTmuxKillData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("terminal: invalid tmux kill request: %v", err)
		return
	}

	sendResult := func(status, output string) {
		payload, marshalErr := json.Marshal(protocol.CommandResultData{
			JobID:     req.JobID,
			SessionID: req.SessionID,
			CommandID: req.CommandID,
			Status:    status,
			Output:    output,
		})
		if marshalErr != nil {
			log.Printf("terminal: failed to marshal tmux kill result for %s: %v", req.JobID, marshalErr)
			return
		}
		if sendErr := transport.Send(protocol.Message{
			Type: protocol.MsgCommandResult,
			ID:   req.JobID,
			Data: payload,
		}); sendErr != nil {
			log.Printf("terminal: failed to send tmux kill result for %s: %v", req.JobID, sendErr)
		}
	}

	tmuxSession := strings.TrimSpace(req.TmuxSession)
	if tmuxSession == "" {
		sendResult("failed", "tmux session name is required")
		return
	}

	tmuxPath, err := exec.LookPath("tmux")
	if err != nil || strings.TrimSpace(tmuxPath) == "" {
		sendResult("failed", "tmux not available")
		return
	}

	timeout := remoteCommandTimeoutFromSeconds(req.Timeout)

	checkCtx, checkCancel := context.WithTimeout(context.Background(), timeout)
	defer checkCancel()

	checkCmd, err := securityruntime.NewCommandContext(checkCtx, tmuxPath, "has-session", "-t", tmuxSession)
	if err != nil {
		sendResult("failed", err.Error())
		return
	}
	if output, err := securityruntime.CaptureCombinedOutput(checkCmd, MaxCommandOutputBytes); err != nil {
		trimmed := TruncateCommandOutput(output, MaxCommandOutputBytes)
		if checkCtx.Err() == context.DeadlineExceeded {
			sendResult("failed", "tmux session check timed out")
			return
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			sendResult("succeeded", "")
			return
		}
		if trimmed == "" {
			trimmed = err.Error()
		}
		sendResult("failed", trimmed)
		return
	}

	killCtx, killCancel := context.WithTimeout(context.Background(), timeout)
	defer killCancel()

	killCmd, err := securityruntime.NewCommandContext(killCtx, tmuxPath, "kill-session", "-t", tmuxSession)
	if err != nil {
		sendResult("failed", err.Error())
		return
	}
	output, err := securityruntime.CaptureCombinedOutput(killCmd, MaxCommandOutputBytes)
	if err != nil {
		trimmed := TruncateCommandOutput(output, MaxCommandOutputBytes)
		if killCtx.Err() == context.DeadlineExceeded {
			sendResult("failed", "tmux session kill timed out")
			return
		}
		if trimmed == "" {
			trimmed = err.Error()
		}
		sendResult("failed", trimmed)
		return
	}
	sendResult("succeeded", TruncateCommandOutput(output, MaxCommandOutputBytes))
}

func sendTerminalStartedWithTmux(transport MessageSender, sessionID string, tmuxAttached bool) {
	data, _ := json.Marshal(protocol.TerminalStartedData{
		SessionID:    sessionID,
		TmuxAttached: tmuxAttached,
	})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgTerminalStarted,
		ID:   sessionID,
		Data: data,
	})
}

func SendTerminalClosed(transport MessageSender, sessionID, reason string) {
	data, _ := json.Marshal(protocol.TerminalCloseData{SessionID: sessionID, Reason: reason})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgTerminalClosed,
		ID:   sessionID,
		Data: data,
	})
}

// DetectShell finds the best available shell on the system.
func DetectShell() string {
	if runtime.GOOS == "windows" {
		for _, shell := range shellCandidatesForOS(runtime.GOOS) {
			if path, err := exec.LookPath(shell); err == nil {
				return path
			}
		}
		return "cmd.exe"
	}

	// Prefer the user's configured shell (SHELL env var).
	if userShell := os.Getenv("SHELL"); userShell != "" {
		// #nosec G703 -- local SHELL env is trusted runtime input on the managed node.
		if _, err := os.Stat(userShell); err == nil {
			return userShell
		}
	}
	// On macOS, prefer zsh (default since Catalina).
	for _, shell := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}
	// Fallback: try PATH lookup.
	for _, shell := range shellCandidatesForOS(runtime.GOOS) {
		if path, err := exec.LookPath(shell); err == nil {
			return path
		}
	}
	return "/bin/sh"
}

func shellCandidatesForOS(goos string) []string {
	if goos == "windows" {
		return []string{"pwsh.exe", "powershell.exe", "cmd.exe"}
	}
	return []string{"zsh", "bash", "sh"}
}
