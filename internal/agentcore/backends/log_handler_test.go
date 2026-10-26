package backends

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type finiteLogBackend struct{}

func (finiteLogBackend) QueryEntries(protocol.JournalQueryData) ([]protocol.LogStreamData, error) {
	return nil, nil
}

func (finiteLogBackend) StreamEntries(_ context.Context, emit func(protocol.LogStreamData)) error {
	for index := range LogBatchMaxEntries + 3 {
		emit(protocol.LogStreamData{Message: fmt.Sprintf("entry-%d", index)})
	}
	return nil
}

type batchLogSender struct{ messages chan protocol.Message }

func (s batchLogSender) Send(message protocol.Message) error { s.messages <- message; return nil }
func (batchLogSender) Connected() bool                       { return true }
func (batchLogSender) AssetID() string                       { return "asset-1" }

// Releasing the batch's string references after sending must not erase the
// serialized entries or the final partial batch.
func TestLogManagerFlushPreservesEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender := batchLogSender{messages: make(chan protocol.Message, 2)}
	manager := &LogManager{Backend: finiteLogBackend{}}
	defer manager.CloseAll()
	manager.Start(ctx, sender)
	next := 0
	for _, count := range []int{LogBatchMaxEntries, 3} {
		select {
		case message := <-sender.messages:
			var batch protocol.LogBatchData
			if err := json.Unmarshal(message.Data, &batch); err != nil {
				t.Fatal(err)
			}
			if len(batch.Entries) != count || batch.AssetID != "asset-1" {
				t.Fatalf("unexpected batch: %+v", batch)
			}
			for _, entry := range batch.Entries {
				if entry.Message != fmt.Sprintf("entry-%d", next) {
					t.Fatalf("entry %d lost or reordered: %q", next, entry.Message)
				}
				next++
			}
		case <-time.After(time.Second):
			t.Fatal("log batch was not flushed")
		}
	}
}
