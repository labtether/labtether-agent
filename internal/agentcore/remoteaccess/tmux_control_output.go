package remoteaccess

import (
	"io"
	"sync"
	"time"
)

const (
	// tmuxOutputChunkBytes is the most terminal output sent in one message.
	tmuxOutputChunkBytes = 64 << 10
	// The Hub queues 256 messages per terminal and closes the stream when the
	// browser falls further behind. A burst of 32 messages goes out at once;
	// after that 32 a second, which is 2 MiB a second of output and leaves the
	// browser eight seconds before that queue fills.
	tmuxOutputBurstMessages  = 32
	tmuxOutputMessagesPerSec = 32
	// tmuxLiveQueueBytes is how much shell output may wait here. A program
	// that prints faster than it can be sent fills it; the terminal then skips
	// ahead (see tmuxControlTerminal.hold) instead of keeping more.
	tmuxLiveQueueBytes = 4 << 20
)

// tmuxOutputQueue holds terminal bytes between the tmux reader and the loop
// that sends them to the Hub. Its size is bounded for shell output, and Read
// paces how often a message leaves.
type tmuxOutputQueue struct {
	mu       sync.Mutex
	buf      []byte
	off      int
	ended    bool // nothing more will be added; Read drains, then EOF
	closed   bool
	tokens   float64
	refilled time.Time

	wake    chan struct{} // data added, ended or closed
	drained chan struct{} // Read took the last byte
	stop    chan struct{} // closed by Close
}

func newTmuxOutputQueue() *tmuxOutputQueue {
	return &tmuxOutputQueue{
		tokens:   tmuxOutputBurstMessages,
		refilled: time.Now(),
		wake:     make(chan struct{}, 1),
		drained:  make(chan struct{}, 1),
		stop:     make(chan struct{}),
	}
}

// addLive queues shell output. It reports false, and queues nothing, when the
// queue is full.
func (q *tmuxOutputQueue) addLive(data []byte) bool {
	q.mu.Lock()
	if len(q.buf)-q.off+len(data) > tmuxLiveQueueBytes {
		q.mu.Unlock()
		return false
	}
	q.buf = append(q.buf, data...)
	q.mu.Unlock()
	q.signal(q.wake)
	return true
}

// addScreen queues a redrawn screen. It is bounded by its maker, not here.
func (q *tmuxOutputQueue) addScreen(data []byte) {
	q.mu.Lock()
	q.buf = append(q.buf, data...)
	q.mu.Unlock()
	q.signal(q.wake)
}

// discard drops what has not been read yet.
func (q *tmuxOutputQueue) discard() {
	q.mu.Lock()
	q.buf, q.off = nil, 0
	q.mu.Unlock()
	q.signal(q.drained)
}

func (q *tmuxOutputQueue) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.buf) - q.off
}

// end marks the stream complete: readers get what is queued, then EOF.
func (q *tmuxOutputQueue) end() {
	q.mu.Lock()
	q.ended = true
	q.mu.Unlock()
	q.signal(q.wake)
}

func (q *tmuxOutputQueue) Close() error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.stop)
	}
	q.buf, q.off = nil, 0
	q.mu.Unlock()
	return nil
}

func (q *tmuxOutputQueue) Read(p []byte) (int, error) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return 0, io.EOF
		}
		if q.off < len(q.buf) {
			wait := q.takeToken()
			if wait > 0 {
				q.mu.Unlock()
				if !q.sleep(wait) {
					return 0, io.EOF
				}
				continue
			}
			n := copy(p, q.buf[q.off:])
			q.off += n
			empty := q.off == len(q.buf)
			if empty {
				q.off = 0
				if cap(q.buf) > tmuxLiveQueueBytes/4 {
					q.buf = nil
				} else {
					q.buf = q.buf[:0]
				}
			}
			q.mu.Unlock()
			if empty {
				q.signal(q.drained)
			}
			return n, nil
		}
		ended := q.ended
		q.mu.Unlock()
		if ended {
			return 0, io.EOF
		}
		select {
		case <-q.wake:
		case <-q.stop:
		}
	}
}

// takeToken spends one message from the budget, or says how long until one
// is free. The caller holds mu.
func (q *tmuxOutputQueue) takeToken() time.Duration {
	now := time.Now()
	q.tokens += now.Sub(q.refilled).Seconds() * tmuxOutputMessagesPerSec
	q.refilled = now
	if q.tokens > tmuxOutputBurstMessages {
		q.tokens = tmuxOutputBurstMessages
	}
	if q.tokens >= 1 {
		q.tokens--
		return 0
	}
	return time.Duration((1 - q.tokens) / tmuxOutputMessagesPerSec * float64(time.Second))
}

func (q *tmuxOutputQueue) sleep(wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-q.stop:
		return false
	}
}

func (q *tmuxOutputQueue) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
