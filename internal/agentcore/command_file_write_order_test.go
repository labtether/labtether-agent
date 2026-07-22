package agentcore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
)

func TestOrderedFileWriteWorkerPreservesChunkOffsets(t *testing.T) {
	transport, responses, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	baseDir := t.TempDir()
	fileMgr := &files.Manager{BaseDir: baseDir, HomeDir: baseDir}
	defer fileMgr.CloseAll()

	requestID := "ordered-upload"
	contents := []byte("installed QA upload payload")
	encode := func(payload protocol.FileWriteData) protocol.Message {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal write payload: %v", err)
		}
		return protocol.Message{Type: protocol.MsgFileWrite, ID: requestID, Data: raw}
	}

	messages := make(chan protocol.Message, 2)
	messages <- encode(protocol.FileWriteData{
		RequestID: requestID,
		Path:      "uploaded.txt",
		Data:      base64.StdEncoding.EncodeToString(contents),
		Offset:    0,
		Done:      false,
	})
	messages <- encode(protocol.FileWriteData{
		RequestID: requestID,
		Path:      "uploaded.txt",
		Offset:    int64(len(contents)),
		Done:      true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runOrderedFileWriteWorker(ctx, transport, fileMgr, messages)
	}()

	select {
	case response := <-responses:
		if response.Type != protocol.MsgFileWritten {
			t.Fatalf("response type=%q, want %q", response.Type, protocol.MsgFileWritten)
		}
		var written protocol.FileWrittenData
		if err := json.Unmarshal(response.Data, &written); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if written.Error != "" || written.BytesWritten != int64(len(contents)) {
			t.Fatalf("write result=%+v", written)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ordered upload completion")
	}

	actual, err := os.ReadFile(filepath.Join(baseDir, "uploaded.txt"))
	if err != nil {
		t.Fatalf("read uploaded file: %v", err)
	}
	if string(actual) != string(contents) {
		t.Fatalf("uploaded content=%q, want %q", actual, contents)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ordered file worker did not stop")
	}
}
