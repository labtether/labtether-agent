package agentcore

import (
	"context"

	"github.com/labtether/protocol"
)

// A stream input worker preserves the WebSocket byte order. A single buffered
// frame keeps memory bounded by the existing control-message read limit and
// still lets the reader process unrelated messages while input is being written.
func runOrderedStreamInput(ctx context.Context, messages <-chan protocol.Message, handle func(protocol.Message)) {
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-messages:
			if !ok || ctx.Err() != nil {
				return
			}
			safeHandler("stream-input", func() { handle(msg) })
		}
	}
}

func enqueueStreamInput(ctx context.Context, messages chan<- protocol.Message, msg protocol.Message) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case messages <- msg:
		return true
	case <-ctx.Done():
		return false
	}
}
