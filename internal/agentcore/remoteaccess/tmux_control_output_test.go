package remoteaccess

import (
	"bytes"
	"testing"
)

// A program that floods right after a re-open filled the queue while the
// redrawn screen was still waiting. The whole queue was dropped, screen
// included, so the terminal never finished drawing. The screen must not count
// as shell output and must survive the drop.
func TestTmuxOutputQueueKeepsWaitingScreenWhenShellOutputOverflows(t *testing.T) {
	q := newTmuxOutputQueue()
	screen := bytes.Repeat([]byte("s"), tmuxLiveQueueBytes+tmuxLiveQueueBytes/2)
	q.addScreen(screen)
	chunk := bytes.Repeat([]byte("l"), 1<<20)
	for i := 0; i < tmuxLiveQueueBytes>>20; i++ {
		if !q.addLive(chunk) {
			t.Fatalf("shell output %d MiB refused behind a waiting screen", i+1)
		}
	}
	if q.addLive(chunk) {
		t.Fatal("shell output past the limit was queued")
	}
	q.discard()
	if got := q.pending(); got != len(screen) {
		t.Fatalf("%d bytes wait after the drop, want the %d-byte screen", got, len(screen))
	}
	select {
	case <-q.drained:
		t.Fatal("queue reported empty while the screen still waits")
	default:
	}
}

// Output a little faster than it is sent never empties the queue. The bytes
// already sent stayed in memory until it did, which could be minutes.
func TestTmuxOutputQueueDoesNotKeepSentBytes(t *testing.T) {
	q := newTmuxOutputQueue()
	q.tokens = 1 << 30 // no pacing in this test
	chunk := bytes.Repeat([]byte("x"), tmuxOutputChunkBytes)
	out := make([]byte, tmuxOutputChunkBytes)
	for i := 0; i < 2048; i++ { // 128 MiB through a queue that is never empty
		if !q.addLive(chunk) || !q.addLive(chunk[:1]) {
			t.Fatalf("round %d: queue refused output it had room for", i)
		}
		q.tokens = 1 << 30
		if n, err := q.Read(out); err != nil || n != len(out) {
			t.Fatalf("round %d: read %d bytes, err %v", i, n, err)
		}
		if held := cap(q.buf); held > 2*tmuxLiveQueueBytes {
			t.Fatalf("round %d: queue holds %d bytes for %d waiting", i, held, q.pending())
		}
	}
}
