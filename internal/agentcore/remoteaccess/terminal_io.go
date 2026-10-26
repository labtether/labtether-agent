package remoteaccess

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/labtether/protocol"
)

// CloseAll terminates all active sessions (called on agent shutdown).
func (tm *TerminalManager) CloseAll() {
	tm.Mu.Lock()
	defer tm.Mu.Unlock()
	for id, pending := range tm.pending {
		pending.cancel()
		delete(tm.pending, id)
	}
	for id, sess := range tm.Sessions {
		sess.terminate()
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
			if sendErr := transport.Send(protocol.Message{
				Type: protocol.MsgTerminalData,
				ID:   sess.sessionID,
				Data: data,
			}); sendErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("terminal: read error for session %s: %v", sess.sessionID, err)
			}
			return
		}
	}
}

// cleanupSession removes only the exact session that still owns its ID. A late
// reader from an old session must never close a replacement with the same ID.
func (tm *TerminalManager) cleanupSession(sess *TerminalSession) bool {
	tm.Mu.Lock()
	current := tm.Sessions[sess.sessionID] == sess
	if current {
		delete(tm.Sessions, sess.sessionID)
	}
	tm.Mu.Unlock()
	sess.close()
	return current
}

func (s *TerminalSession) terminate() {
	s.close()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

func startPipeBackedTerminal(cmd *exec.Cmd) (io.WriteCloser, io.ReadCloser, <-chan error, error) {
	return startTerminalPipeBridge(func(stdin io.Reader, output io.Writer) error {
		cmd.Stdin = stdin
		cmd.Stdout = output
		cmd.Stderr = output
		return cmd.Start()
	}, cmd.Wait)
}

// Own the pipe read end instead of using StdoutPipe/StderrPipe: exec.Cmd.Wait
// closes those readers, which can discard final output. Passing an *os.File as
// both output writers also avoids exec-owned copy workers delaying Wait when a
// descendant inherits the writer. The session's drain timer closes our reader.
func startTerminalPipeBridge(start func(io.Reader, io.Writer) error, wait func() error) (io.WriteCloser, io.ReadCloser, <-chan error, error) {
	childInput, input, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	defer childInput.Close()
	output, childOutput, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return nil, nil, nil, err
	}
	defer childOutput.Close()
	if err := start(childInput, childOutput); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, nil, nil, err
	}

	processDone := make(chan error, 1)
	go func() {
		err := wait()
		_ = input.Close()
		processDone <- err
		close(processDone)
	}()
	return input, output, processDone, nil
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

func (s *TerminalSession) close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.closeOnce.Do(func() {
		if sessInput := s.inputWriter; sessInput != nil {
			_ = sessInput.Close()
		}
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
