package remoteaccess

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/creack/pty"
	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
	"io"
	"log"
	"os/exec"
	"time"
)

type pendingTerminalStart struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// HandleTerminalStart remains synchronous for direct callers.
func (tm *TerminalManager) HandleTerminalStart(transport MessageSender, msg protocol.Message) {
	if start := tm.PrepareTerminalStart(transport, msg); start != nil {
		start()
	}
}

// PrepareTerminalStart reserves in socket receipt order; the returned work may
// run asynchronously. Close/CloseAll cancels this exact start before promotion.
func (tm *TerminalManager) PrepareTerminalStart(transport MessageSender, msg protocol.Message) func() {
	var req protocol.TerminalStartData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("terminal: invalid start request: %v", err)
		return nil
	}

	if req.SessionID == "" {
		log.Printf("terminal: start request missing session_id")
		return nil
	}

	tm.Mu.Lock()
	if _, exists := tm.Sessions[req.SessionID]; exists || tm.pending[req.SessionID] != nil {
		tm.Mu.Unlock()
		return nil
	}
	if len(tm.Sessions)+len(tm.pending) >= MaxTerminalSessions {
		tm.Mu.Unlock()
		return func() { SendTerminalClosed(transport, req.SessionID, "max terminal sessions reached") }
	}
	if tm.pending == nil {
		tm.pending = make(map[string]*pendingTerminalStart)
	}
	startCtx := context.Background()
	if owner, ok := transport.(interface{ Context() context.Context }); ok {
		startCtx = owner.Context()
	}
	ctx, cancel := context.WithCancel(startCtx)
	pending := &pendingTerminalStart{ctx: ctx, cancel: cancel}
	tm.pending[req.SessionID] = pending
	tm.Mu.Unlock()
	return func() { tm.startTerminal(transport, req, pending) }
}

func (tm *TerminalManager) startTerminal(transport MessageSender, req protocol.TerminalStartData, pending *pendingTerminalStart) {
	defer func() {
		tm.Mu.Lock()
		if tm.pending[req.SessionID] == pending {
			delete(tm.pending, req.SessionID)
			pending.cancel()
		}
		tm.Mu.Unlock()
	}()
	if pending.ctx.Err() != nil {
		return
	}
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
			cmd, err = securityruntime.NewCommandContext(pending.ctx, tmuxPath, "new-session", "-A", "-s", req.TmuxSession)
			if err != nil {
				log.Printf("terminal: tmux command blocked by runtime policy for session %s: %v", req.SessionID, err)
				tm.sendPendingTerminalFailure(transport, req.SessionID, pending, "failed to start tmux: "+err.Error())
				return
			}
			tmuxAttached = true
		} else {
			log.Printf("terminal: tmux requested but not found for session %s, falling back to plain shell", req.SessionID)
			cmd, err = securityruntime.NewCommandContext(pending.ctx, shell)
			if err != nil {
				log.Printf("terminal: shell command blocked by runtime policy for session %s: %v", req.SessionID, err)
				tm.sendPendingTerminalFailure(transport, req.SessionID, pending, "failed to start shell: "+err.Error())
				return
			}
		}
	} else {
		cmd, err = securityruntime.NewCommandContext(pending.ctx, shell)
		if err != nil {
			log.Printf("terminal: shell command blocked by runtime policy for session %s: %v", req.SessionID, err)
			tm.sendPendingTerminalFailure(transport, req.SessionID, pending, "failed to start shell: "+err.Error())
			return
		}
	}
	cmd.Env = append(securityruntime.SanitizedChildEnv(), "TERM=xterm-256color")

	startPTY := tm.startPTY
	if startPTY == nil {
		startPTY = pty.StartWithSize
	}
	ptmx, err := startPTY(cmd, &pty.Winsize{
		Cols: ClampUint16(cols),
		Rows: ClampUint16(rows),
	})
	var input io.WriteCloser
	var output io.ReadCloser
	var pipeProcessDone <-chan error
	if errors.Is(err, pty.ErrUnsupported) {
		// creack/pty deliberately reports unsupported on Windows. Keep the
		// terminal usable with a bounded stdin/stdout pipe bridge until a native
		// ConPTY backend is available; process execution and input still pass
		// through the same allowlist and authenticated agent channel.
		input, output, pipeProcessDone, err = startPipeBackedTerminal(cmd)
	}
	if err != nil {
		log.Printf("terminal: failed to start PTY for session %s: %v", req.SessionID, err)
		tm.sendPendingTerminalFailure(transport, req.SessionID, pending, "failed to start shell: "+err.Error())
		return
	}

	sess := &TerminalSession{
		sessionID:  req.SessionID,
		cancel:     pending.cancel,
		Ptmx:       ptmx,
		input:      input,
		output:     output,
		cmd:        cmd,
		done:       make(chan struct{}),
		outputDone: make(chan struct{}),
	}

	inputStream := input
	if ptmx != nil {
		inputStream = ptmx
	}
	sess.inputWriter = streaminput.New(inputStream, func(error) {
		sess.close()
		if sess.cmd != nil && sess.cmd.Process != nil {
			_ = sess.cmd.Process.Kill()
		}
	})

	tm.Mu.Lock()
	if tm.pending[req.SessionID] != pending || pending.ctx.Err() != nil {
		tm.Mu.Unlock()
		sess.close()
		pending.cancel()
		if pipeProcessDone != nil {
			<-pipeProcessDone
		} else {
			_ = cmd.Wait()
		}
		return
	}
	delete(tm.pending, req.SessionID)
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
		defer close(sess.outputDone)
		tm.streamOutput(transport, sess)
		if tm.cleanupSession(sess) {
			SendTerminalClosed(transport, req.SessionID, sess.inputWriter.Reason("shell exited"))
		}
	}()

	// Wait for process exit, preserving normal final output before bounding
	// a descendant that keeps the terminal open after its shell has exited.
	go func() {
		if pipeProcessDone != nil {
			_ = <-pipeProcessDone
		} else {
			_ = cmd.Wait()
		}
		close(sess.done)
		select {
		case <-sess.outputDone:
		case <-time.After(terminalOutputDrainTimeout):
			// Give normal output time to drain, then release the orphaned stream.
			sess.close()
		}
	}()
}

func (tm *TerminalManager) sendPendingTerminalFailure(transport MessageSender, id string, pending *pendingTerminalStart, reason string) {
	tm.Mu.Lock()
	current := tm.pending[id] == pending && pending.ctx.Err() == nil
	tm.Mu.Unlock()
	if current {
		SendTerminalClosed(transport, id, reason)
	}
}
