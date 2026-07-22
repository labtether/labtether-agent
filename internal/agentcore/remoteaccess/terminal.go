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

	"github.com/creack/pty"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// TerminalSession tracks an active PTY shell session on the agent.
type TerminalSession struct {
	sessionID string
	Ptmx      *os.File
	input     io.WriteCloser
	output    io.ReadCloser
	cmd       *exec.Cmd
	done      chan struct{}
	closeOnce sync.Once
}

const MaxTerminalSessions = 10

// TerminalManager manages PTY sessions on the agent.
type TerminalManager struct {
	Mu       sync.Mutex
	Sessions map[string]*TerminalSession
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

// HandleTerminalStart spawns a new PTY shell and starts streaming output.
func (tm *TerminalManager) HandleTerminalStart(transport MessageSender, msg protocol.Message) {
	var req protocol.TerminalStartData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("terminal: invalid start request: %v", err)
		return
	}

	if req.SessionID == "" {
		log.Printf("terminal: start request missing session_id")
		return
	}

	tm.Mu.Lock()
	if len(tm.Sessions) >= MaxTerminalSessions {
		tm.Mu.Unlock()
		log.Printf("terminal: max sessions (%d) reached", MaxTerminalSessions)
		SendTerminalClosed(transport, req.SessionID, "max terminal sessions reached")
		return
	}
	if _, exists := tm.Sessions[req.SessionID]; exists {
		tm.Mu.Unlock()
		log.Printf("terminal: session %s already exists", req.SessionID)
		return
	}
	tm.Mu.Unlock()

	// Find a shell
	shell := req.Shell
	if shell == "" {
		shell = DetectShell()
	}

	cols := req.Cols
	rows := req.Rows
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 40
	}

	// Determine command to run: tmux session or plain shell.
	tmuxAttached := false
	var cmd *exec.Cmd
	var err error
	if req.UseTmux && req.TmuxSession != "" {
		tmuxPath, lookErr := exec.LookPath("tmux")
		if lookErr == nil && tmuxPath != "" {
			// tmux new-session -A -s <name> creates or attaches to an existing session.
			cmd, err = securityruntime.NewCommand(tmuxPath, "new-session", "-A", "-s", req.TmuxSession)
			if err != nil {
				log.Printf("terminal: tmux command blocked by runtime policy for session %s: %v", req.SessionID, err)
				SendTerminalClosed(transport, req.SessionID, "failed to start tmux: "+err.Error())
				return
			}
			tmuxAttached = true
		} else {
			log.Printf("terminal: tmux requested but not found for session %s, falling back to plain shell", req.SessionID)
			cmd, err = securityruntime.NewCommand(shell)
			if err != nil {
				log.Printf("terminal: shell command blocked by runtime policy for session %s: %v", req.SessionID, err)
				SendTerminalClosed(transport, req.SessionID, "failed to start shell: "+err.Error())
				return
			}
		}
	} else {
		cmd, err = securityruntime.NewCommand(shell)
		if err != nil {
			log.Printf("terminal: shell command blocked by runtime policy for session %s: %v", req.SessionID, err)
			SendTerminalClosed(transport, req.SessionID, "failed to start shell: "+err.Error())
			return
		}
	}
	cmd.Env = append(securityruntime.SanitizedChildEnv(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
	var input io.WriteCloser
	var output io.ReadCloser
	if errors.Is(err, pty.ErrUnsupported) {
		// creack/pty deliberately reports unsupported on Windows. Keep the
		// terminal usable with a bounded stdin/stdout pipe bridge until a native
		// ConPTY backend is available; process execution and input still pass
		// through the same allowlist and authenticated agent channel.
		input, output, err = startPipeBackedTerminal(cmd)
	}
	if err != nil {
		log.Printf("terminal: failed to start PTY for session %s: %v", req.SessionID, err)
		SendTerminalClosed(transport, req.SessionID, "failed to start shell: "+err.Error())
		return
	}

	sess := &TerminalSession{
		sessionID: req.SessionID,
		Ptmx:      ptmx,
		input:     input,
		output:    output,
		cmd:       cmd,
		done:      make(chan struct{}),
	}

	tm.Mu.Lock()
	tm.Sessions[req.SessionID] = sess
	tm.Mu.Unlock()

	// Notify hub that terminal is ready
	sendTerminalStartedWithTmux(transport, req.SessionID, tmuxAttached)

	// Stream PTY output → hub. The streamOutput goroutine is responsible
	// for final teardown once its Read loop exits naturally (on EOF/EIO
	// after the child closes its slave PTY). Closing Ptmx elsewhere while
	// streamOutput is still reading causes "file already closed" errors
	// and loses any buffered output, which breaks large-output tests.
	go func() {
		tm.streamOutput(transport, sess)
		tm.cleanup(req.SessionID)
		SendTerminalClosed(transport, req.SessionID, "shell exited")
	}()

	// Observe process exit for lifecycle signalling only. Do NOT close
	// the PTY here — streamOutput owns that.
	go func() {
		_ = cmd.Wait()
		close(sess.done)
	}()
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

	_, _ = sess.write(decoded)
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
	sess, ok := tm.Sessions[req.SessionID]
	tm.Mu.Unlock()
	if !ok {
		return
	}

	// Close terminal I/O — this will cause the shell process to exit.
	sess.close()
	if sess.cmd.Process != nil {
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

// CloseAll terminates all active sessions (called on agent shutdown).
func (tm *TerminalManager) CloseAll() {
	tm.Mu.Lock()
	defer tm.Mu.Unlock()
	for id, sess := range tm.Sessions {
		sess.close()
		if sess.cmd.Process != nil {
			_ = sess.cmd.Process.Kill()
		}
		delete(tm.Sessions, id)
	}
}

// streamOutput reads from the PTY and sends output to the hub.
func (tm *TerminalManager) streamOutput(transport MessageSender, sess *TerminalSession) {
	buf := make([]byte, 4096)
	for {
		n, err := sess.read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			data, _ := json.Marshal(protocol.TerminalDataPayload{
				SessionID: sess.sessionID,
				Data:      encoded,
			})
			_ = transport.Send(protocol.Message{
				Type: protocol.MsgTerminalData,
				ID:   sess.sessionID,
				Data: data,
			})
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("terminal: read error for session %s: %v", sess.sessionID, err)
			}
			return
		}
	}
}

func (tm *TerminalManager) cleanup(sessionID string) {
	tm.Mu.Lock()
	defer tm.Mu.Unlock()
	if sess, ok := tm.Sessions[sessionID]; ok {
		sess.close()
		delete(tm.Sessions, sessionID)
	}
}

func startPipeBackedTerminal(cmd *exec.Cmd) (io.WriteCloser, io.ReadCloser, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, nil, err
	}
	combinedReader, combinedWriter := io.Pipe()
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		_ = combinedReader.Close()
		_ = combinedWriter.Close()
		return nil, nil, err
	}

	var copies sync.WaitGroup
	copies.Add(2)
	copyStream := func(source io.ReadCloser) {
		defer copies.Done()
		defer source.Close()
		_, _ = io.Copy(combinedWriter, source)
	}
	go copyStream(stdout)
	go copyStream(stderr)
	go func() {
		copies.Wait()
		_ = combinedWriter.Close()
	}()

	return stdin, combinedReader, nil
}

func (s *TerminalSession) read(buf []byte) (int, error) {
	if s.Ptmx != nil {
		return s.Ptmx.Read(buf)
	}
	if s.output == nil {
		return 0, io.EOF
	}
	return s.output.Read(buf)
}

func (s *TerminalSession) write(data []byte) (int, error) {
	if s.Ptmx != nil {
		return s.Ptmx.Write(data)
	}
	if s.input == nil {
		return 0, io.ErrClosedPipe
	}
	return s.input.Write(data)
}

func (s *TerminalSession) close() {
	s.closeOnce.Do(func() {
		if s.Ptmx != nil {
			_ = s.Ptmx.Close()
		}
		if s.input != nil {
			_ = s.input.Close()
		}
		if s.output != nil {
			_ = s.output.Close()
		}
	})
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
