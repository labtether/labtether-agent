package agentcore

import (
	"errors"
	"sync"
)

// A permanent item failure retires only that item instead of blocking its tail.
var errDiscardBufferedItem = errors.New("discard invalid buffered item")

// RingBuffer keeps at most capacity entries, overwriting the oldest when full.
// Flush serializes delivery without blocking producers behind a slow sender.
type RingBuffer[T any] struct {
	mu          sync.Mutex
	flushMu     sync.Mutex
	data        []T
	head        int
	size        int
	cap         int
	headVersion uint64
}

func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	if capacity <= 0 {
		capacity = 60
	}
	return &RingBuffer[T]{data: make([]T, capacity), cap: capacity}
}

func (rb *RingBuffer[T]) Push(item T) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	idx := (rb.head + rb.size) % rb.cap
	rb.data[idx] = item
	if rb.size < rb.cap {
		rb.size++
	} else {
		rb.head = (rb.head + 1) % rb.cap
		rb.headVersion++
	}
}

// Flush attempts up to capacity sends in queue order. A concurrent flush returns
// immediately; its producer leaves its samples for this owner or a later flush.
// Failed sends stay queued unless producers overwrite them under the normal
// capacity policy. A send wrapping errDiscardBufferedItem discards only that
// exact item and continues. Success is not acknowledged persistence.
func (rb *RingBuffer[T]) Flush(send func(T) error) error {
	if !rb.flushMu.TryLock() {
		return nil
	}
	defer rb.flushMu.Unlock()
	for i := 0; i < rb.cap; i++ {
		rb.mu.Lock()
		if rb.size == 0 {
			rb.mu.Unlock()
			return nil
		}
		sample, version := rb.data[rb.head], rb.headVersion
		rb.mu.Unlock()
		if err := send(sample); err != nil && !errors.Is(err, errDiscardBufferedItem) {
			return err
		}
		rb.mu.Lock()
		// Producers may have overwritten this in-flight head. Never remove its
		// replacement, even when the circular index has wrapped back to the same slot.
		if rb.size > 0 && rb.headVersion == version {
			var zero T
			rb.data[rb.head] = zero
			rb.head = (rb.head + 1) % rb.cap
			rb.size--
			rb.headVersion++
		}
		rb.mu.Unlock()
	}
	return nil
}

// Drain returns and releases all retained entries in oldest-first order.
func (rb *RingBuffer[T]) Drain() []T {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.size == 0 {
		return nil
	}
	out := make([]T, rb.size)
	var zero T
	for i := range out {
		idx := (rb.head + i) % rb.cap
		out[i] = rb.data[idx]
		rb.data[idx] = zero
	}
	rb.head = 0
	rb.size = 0
	rb.headVersion++
	return out
}

func (rb *RingBuffer[T]) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}
