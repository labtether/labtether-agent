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
	messages := make(chan orderedFileWrite, 2)
	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldCancel()
	for _, item := range []struct {
		ctx  context.Context
		name string
	}{{oldCtx, "old"}, {context.Background(), "fresh"}} {
		raw, _ := json.Marshal(protocol.FileWriteData{RequestID: item.name, Path: item.name + ".txt", Data: base64.StdEncoding.EncodeToString([]byte(item.name)), Done: true})
		messages <- orderedFileWrite{ctx: item.ctx, transport: transport, message: protocol.Message{Type: protocol.MsgFileWrite, Data: raw}}
	}
	close(messages)
	done := make(chan struct{})
	go func() { defer close(done); runOrderedFileWriteWorker(context.Background(), manager, messages) }()
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
func TestOrderedFileWriteFullQueueFailsOnlyOriginSocket(t *testing.T) {
	transport, _, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	transport.mu.Lock()
	transport.connected = true
	transport.connectionCtx, transport.connectionCancel = context.WithCancel(context.Background())
	conn := transport.conn
	transport.mu.Unlock()
	sender := transport.senderForConnection(conn)
	messages := make(chan orderedFileWrite, 1)
	messages <- orderedFileWrite{}
	done := make(chan bool, 1)
	go func() {
		done <- enqueueOrderedFileWrite(sender.Context(), sender, messages, protocol.Message{Type: protocol.MsgFileWrite})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full queue blocked socket reader")
	}
	if transport.socketOpen() {
		t.Fatal("full queue silently dropped upload without disconnect")
	}
}
