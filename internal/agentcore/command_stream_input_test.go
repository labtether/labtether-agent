package agentcore

import (
	"context"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestStreamInputPreservesOrderAcrossSlowWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(chan protocol.Message, 1)
	firstEntered, releaseFirst, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var order []string
	go func() {
		defer close(done)
		runOrderedStreamInput(ctx, messages, func(msg protocol.Message) {
			if msg.ID == "first" {
				close(firstEntered)
				<-releaseFirst
			}
			order = append(order, msg.ID)
		})
	}()
	if !enqueueStreamInput(ctx, messages, protocol.Message{ID: "first"}) {
		t.Fatal("first input rejected")
	}
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first input never entered")
	}
	if !enqueueStreamInput(ctx, messages, protocol.Message{ID: "second"}) {
		t.Fatal("second input rejected")
	}
	close(releaseFirst)
	close(messages)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("input worker did not drain")
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("byte order changed: %v", order)
	}
}

func TestStreamInputCancellationDoesNotApplyBufferedBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	messages := make(chan protocol.Message, 1)
	messages <- protocol.Message{ID: "stale"}
	cancel()
	runOrderedStreamInput(ctx, messages, func(protocol.Message) { t.Fatal("cancelled input was applied") })
	if enqueueStreamInput(ctx, messages, protocol.Message{ID: "later"}) {
		t.Fatal("cancelled queue accepted input")
	}
}
