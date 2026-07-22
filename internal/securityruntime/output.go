package securityruntime

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
)

const (
	// DefaultCommandOutputLimit is the hard in-memory ceiling used by the
	// command-output helpers. It is deliberately below the agent's control
	// message limit while leaving room for large inventory responses.
	DefaultCommandOutputLimit = 8 * 1024 * 1024
	commandStderrCaptureLimit = 64 * 1024
)

// ErrCommandOutputLimit reports that a subprocess produced more output than
// the configured in-memory capture ceiling. The subprocess is still drained
// to completion so it cannot block on a full stdout or stderr pipe.
var ErrCommandOutputLimit = errors.New("command output exceeded capture limit")

// CappedRetainingWriter retains only the first maxBytes written while
// reporting every write as consumed. It is safe for concurrent stdout and
// stderr copier goroutines.
type CappedRetainingWriter struct {
	mu        sync.Mutex
	data      []byte
	maxBytes  int
	truncated bool
}

// NewCappedRetainingWriter constructs a draining writer with a fixed retention
// ceiling. Non-positive limits retain no bytes but still drain all writes.
func NewCappedRetainingWriter(maxBytes int) *CappedRetainingWriter {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &CappedRetainingWriter{maxBytes: maxBytes}
}

// Write implements io.Writer. It always consumes the complete input even when
// the retention ceiling has already been reached.
func (w *CappedRetainingWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	written := len(payload)
	remaining := w.maxBytes - len(w.data)
	if remaining > 0 {
		if remaining > len(payload) {
			remaining = len(payload)
		}
		w.data = append(w.data, payload[:remaining]...)
	}
	if remaining < len(payload) {
		w.truncated = true
	}
	return written, nil
}

// WriteByte appends one byte when capacity remains and otherwise drains it.
func (w *CappedRetainingWriter) WriteByte(value byte) error {
	_, err := w.Write([]byte{value})
	return err
}

// Bytes returns a stable snapshot of the retained prefix.
func (w *CappedRetainingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.data...)
}

// Len returns the number of bytes currently retained.
func (w *CappedRetainingWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.data)
}

// Truncated reports whether at least one byte was discarded.
func (w *CappedRetainingWriter) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

// CaptureCombinedOutput runs cmd while retaining at most maxBytes of its
// combined stdout and stderr. Overflow is reported via ErrCommandOutputLimit;
// any process error remains discoverable with errors.Is/errors.As.
func CaptureCombinedOutput(cmd *exec.Cmd, maxBytes int) ([]byte, error) {
	if cmd == nil {
		return nil, errors.New("command is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("command output limit must be positive")
	}
	if cmd.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	if cmd.Stderr != nil {
		return nil, errors.New("exec: Stderr already set")
	}

	output := NewCappedRetainingWriter(maxBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	runErr := cmd.Run()
	retained := output.Bytes()
	if !output.Truncated() {
		return retained, runErr
	}

	limitErr := fmt.Errorf("%w (%d bytes)", ErrCommandOutputLimit, maxBytes)
	if runErr != nil {
		return retained, errors.Join(runErr, limitErr)
	}
	return retained, limitErr
}

// CaptureOutput runs cmd while retaining at most maxBytes of stdout. Stderr is
// captured with a separate small ceiling for exec.ExitError compatibility.
func CaptureOutput(cmd *exec.Cmd, maxBytes int) ([]byte, error) {
	if cmd == nil {
		return nil, errors.New("command is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("command output limit must be positive")
	}
	if cmd.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}

	stdout := NewCappedRetainingWriter(maxBytes)
	cmd.Stdout = stdout

	var stderr *CappedRetainingWriter
	if cmd.Stderr == nil {
		stderr = NewCappedRetainingWriter(commandStderrCaptureLimit)
		cmd.Stderr = stderr
	}

	runErr := cmd.Run()
	if stderr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitErr.Stderr = stderr.Bytes()
		}
	}

	retained := stdout.Bytes()
	if !stdout.Truncated() {
		return retained, runErr
	}

	limitErr := fmt.Errorf("%w (%d bytes)", ErrCommandOutputLimit, maxBytes)
	if runErr != nil {
		return retained, errors.Join(runErr, limitErr)
	}
	return retained, limitErr
}
