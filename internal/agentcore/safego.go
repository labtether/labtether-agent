package agentcore

import (
	"context"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// SafeGo launches fn in a goroutine with panic recovery. If fn panics,
// the panic is logged and fn is restarted after a 1-second backoff.
// Exits when ctx is cancelled.
func SafeGo(ctx context.Context, wg *sync.WaitGroup, name string, fn func(ctx context.Context)) {
	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		for {
			if ctx.Err() != nil {
				return
			}
			func() {
				defer func() {
					if err := recover(); err != nil {
						log.Printf("safego[%s]: panic recovered: %v\n%s", name, err, debug.Stack())
					}
				}()
				fn(ctx)
			}()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
}

// safeHandler wraps fn with panic recovery for use in message handler goroutines.
func safeHandler(name string, fn func()) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("handler[%s]: panic recovered: %v\n%s", name, err, debug.Stack())
		}
	}()
	fn()
}
