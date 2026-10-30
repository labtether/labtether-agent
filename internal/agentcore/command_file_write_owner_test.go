package agentcore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOrderedFileWriteSkipsCanceledSocketAndKeepsFreshUpload(t *testing.T) {
	transport, responses, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	dir := t.TempDir()
	manager := &files.Manager{BaseDir: dir, HomeDir: dir}
	defer manager.CloseAll()
	queue := newFileWriteQueue(2, time.Second)
	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldCancel()
	for _, item := range []struct {
		ctx  context.Context
		name string
	}{{oldCtx, "old"}, {context.Background(), "fresh"}} {
		raw, _ := json.Marshal(protocol.FileWriteData{RequestID: item.name, Path: item.name + ".txt", Data: base64.StdEncoding.EncodeToString([]byte(item.name)), Done: true})
		queue.messages <- orderedFileWrite{ctx: item.ctx, transport: transport, message: protocol.Message{Type: protocol.MsgFileWrite, Data: raw}}
	}
	close(queue.messages)
	done := make(chan struct{})
	go func() { defer close(done); queue.run(context.Background(), manager) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("file worker did not finish")
	}
	if _, err := os.Stat(filepath.Join(dir, "old.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled socket created upload: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "fresh.txt"))
	if err != nil || string(data) != "fresh" {
		t.Fatalf("fresh upload: %q %v", data, err)
	}
	select {
	case msg := <-responses:
		var ack protocol.FileWrittenData
		if json.Unmarshal(msg.Data, &ack) != nil || ack.RequestID != "fresh" {
			t.Fatalf("wrong socket response: %s", msg.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("fresh ack missing")
	}
}

// Risk: on Windows a slow disk filled the 64-chunk queue and the agent closed
// its Hub connection, so uploads of 8 MiB or more failed. A full queue must
// wait for the writer; a writer that stays stuck fails only that upload.
func TestFileWriteQueueWaitsForSlowWriterAndFailsOnlyStuckUpload(t *testing.T) {
	transport, responses, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	transport.mu.Lock()
	transport.connected = true
	transport.connectionCtx, transport.connectionCancel = context.WithCancel(context.Background())
	conn := transport.conn
	transport.mu.Unlock()
	sender := transport.senderForConnection(conn)
	dir := t.TempDir()
	manager := &files.Manager{BaseDir: dir, HomeDir: dir}
	defer manager.CloseAll()
	chunk := func(id string, offset int64) protocol.Message {
		raw, _ := json.Marshal(protocol.FileWriteData{RequestID: id, Path: id + ".bin", Offset: offset,
			Data: base64.StdEncoding.EncodeToString([]byte("abc"))})
		return protocol.Message{Type: protocol.MsgFileWrite, ID: id, Data: raw}
	}

	// Slow writer: the read loop waits, then queues the chunk once a slot frees.
	slow := newFileWriteQueue(1, 5*time.Second)
	slow.messages <- orderedFileWrite{}
	queued := make(chan bool, 1)
	go func() { queued <- slow.enqueue(sender.Context(), sender, chunk("slow", 3)) }()
	select {
	case <-queued:
		t.Fatal("full queue did not wait for the writer")
	case <-time.After(50 * time.Millisecond):
	}
	<-slow.messages
	if ok := <-queued; !ok || len(slow.messages) != 1 {
		t.Fatalf("slow writer chunk not queued: ok=%v len=%d", ok, len(slow.messages))
	}

	// Stuck writer: only the stuck upload fails; the socket stays open.
	if _, err := manager.WriteChunk(protocol.FileWriteData{RequestID: "stuck", Path: "stuck.bin",
		Data: base64.StdEncoding.EncodeToString([]byte("abc"))}); err != nil {
		t.Fatal(err)
	}
	stuck := newFileWriteQueue(1, 20*time.Millisecond)
	stuck.messages <- orderedFileWrite{ctx: sender.Context(), transport: sender, message: chunk("stuck", 3), requestID: "stuck"}
	if !stuck.enqueue(sender.Context(), sender, chunk("stuck", 6)) {
		t.Fatal("stuck writer stopped the read loop")
	}
	var failure protocol.FileWrittenData
	_ = json.Unmarshal(waitForCapturedAgentMessage(t, responses, protocol.MsgFileWritten, time.Second).Data, &failure)
	if failure.RequestID != "stuck" || failure.Error == "" {
		t.Fatalf("stuck upload result = %+v, want an error for it", failure)
	}
	if !transport.socketOpen() {
		t.Fatal("stuck upload closed the Hub connection")
	}
	stuck.wait = time.Hour // a later chunk of the failed upload must be dropped, not wait
	if !stuck.enqueue(sender.Context(), sender, chunk("stuck", 9)) || len(stuck.messages) != 1 {
		t.Fatal("later chunk of the failed upload was not dropped")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go stuck.run(ctx, manager)
	deadline := time.Now().Add(time.Second)
	for manager.HasPendingWrite("stuck") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if manager.HasPendingWrite("stuck") {
		t.Fatal("failed upload kept its temporary file")
	}
}
