// Package streaminput serializes bounded input to one session's stream.
package streaminput

import (
	"errors"
	"io"
	"sync"
)

const (
	MaxQueuedMessages = 64
	MaxQueuedBytes    = 1024 * 1024
)

var ErrBacklog = errors.New("session input backlog exceeded; session closed")

// Writer owns one stream, including closing it. Enqueue never waits for stream
// I/O, so a stopped backend cannot keep the Hub's close request from arriving.
// Overflow fails the session explicitly instead of losing or reordering bytes.
type Writer struct {
	mu          sync.Mutex
	dst         io.WriteCloser
	pending     chan []byte
	done        chan struct{}
	stopped     bool
	failure     error
	queuedBytes int
	onFailure   func(error)
}

func New(dst io.WriteCloser, onFailure func(error)) *Writer {
	w := &Writer{dst: dst, pending: make(chan []byte, MaxQueuedMessages), done: make(chan struct{}), onFailure: onFailure}
	go w.run()
	return w
}

// Enqueue takes ownership of data. Callers must not modify it after this call.
func (w *Writer) Enqueue(data []byte) error {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return io.ErrClosedPipe
	}
	if len(data) == 0 {
		w.mu.Unlock()
		return nil
	}
	if len(data) <= MaxQueuedBytes-w.queuedBytes {
		select {
		case w.pending <- data:
			w.queuedBytes += len(data)
			w.mu.Unlock()
			return nil
		default:
		}
	}
	w.mu.Unlock()
	w.stop(ErrBacklog)
	return ErrBacklog
}

// Close aborts both the active write and queued input. Queued bytes retain the
// old stream and can never be delivered to a new session with the same ID.
func (w *Writer) Close() error {
	w.stop(nil)
	return nil
}

func (w *Writer) stop(err error) {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.stopped = true
	w.failure = err
	w.mu.Unlock()
	// Record the cause before Close wakes the output reader and emits its final
	// close message. The callback may cancel/close local resources, but must
	// never wait for stream I/O or send messages over the transport.
	if err != nil && w.onFailure != nil {
		w.onFailure(err)
	}
	close(w.done)
	_ = w.dst.Close()
}

func (w *Writer) run() {
	for {
		select {
		case <-w.done:
			return
		case data := <-w.pending:
			w.mu.Lock()
			stopped := w.stopped
			w.mu.Unlock()
			if stopped {
				return
			}
			n, err := w.dst.Write(data)
			if err == nil && n != len(data) {
				err = io.ErrShortWrite
			}
			if err != nil {
				w.stop(err)
				return
			}
			w.mu.Lock()
			w.queuedBytes -= len(data)
			w.mu.Unlock()
		}
	}
}

// Reason returns the input failure, if any, for the session's close response.
func (w *Writer) Reason(fallback string) string {
	if w == nil {
		return fallback
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failure != nil {
		return w.failure.Error()
	}
	return fallback
}
