package agentcore

import (
	"encoding/base64"
	"encoding/json"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileManagerReadEmitsDataAndDone(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	filePath := filepath.Join(root, "sample.txt")
	if err := os.WriteFile(filePath, []byte("hello from file manager"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	fm := &files.Manager{
		BaseDir: root,
	}

	raw, err := json.Marshal(protocol.FileReadData{
		RequestID: "req-read",
		Path:      "sample.txt",
	})
	if err != nil {
		t.Fatalf("marshal file read request: %v", err)
	}
	fm.HandleFileRead(transport, protocol.Message{Data: raw})

	var content strings.Builder
	deadline := time.After(2 * time.Second)
	for {
		select {
		case msg, ok := <-messages:
			if !ok {
				t.Fatal("transport closed before file read completed")
			}
			if msg.Type != protocol.MsgFileData {
				continue
			}
			var payload protocol.FileDataPayload
			if err := json.Unmarshal(msg.Data, &payload); err != nil {
				t.Fatalf("decode file data payload: %v", err)
			}
			decoded, err := base64.StdEncoding.DecodeString(payload.Data)
			if err != nil {
				t.Fatalf("decode file chunk: %v", err)
			}
			content.Write(decoded)
			if payload.Done {
				if payload.Error != "" {
					t.Fatalf("expected successful read, got error %q", payload.Error)
				}
				if content.String() != "hello from file manager" {
					t.Fatalf("unexpected file content %q", content.String())
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for file read result")
		}
	}
}

func TestFileManagerWriteCompletesAndPersistsFile(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	fm := &files.Manager{
		BaseDir: root,
	}

	raw, err := json.Marshal(protocol.FileWriteData{
		RequestID: "req-write",
		Path:      "nested/output.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("written-by-agent")),
		Done:      true,
	})
	if err != nil {
		t.Fatalf("marshal file write request: %v", err)
	}
	fm.HandleFileWrite(transport, protocol.Message{Data: raw})

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileWritten, 2*time.Second)
	var written protocol.FileWrittenData
	if err := json.Unmarshal(msg.Data, &written); err != nil {
		t.Fatalf("decode file written payload: %v", err)
	}
	if written.Error != "" {
		t.Fatalf("expected successful write, got error %q", written.Error)
	}
	if written.BytesWritten != int64(len("written-by-agent")) {
		t.Fatalf("unexpected bytes_written %d", written.BytesWritten)
	}

	data, err := os.ReadFile(filepath.Join(root, "nested/output.txt"))
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if string(data) != "written-by-agent" {
		t.Fatalf("unexpected persisted content %q", string(data))
	}

	if fm.HasPendingWrite("req-write") {
		t.Fatalf("expected pending writer cleanup after completed write")
	}
}

func TestFileManagerWriteFinalizesOnEmptyDoneMarker(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	fm := &files.Manager{
		BaseDir: root,
	}

	firstChunk := strings.Repeat("w", files.FileChunkSize)
	firstRaw, err := json.Marshal(protocol.FileWriteData{
		RequestID: "req-write-boundary",
		Path:      "boundary/output.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte(firstChunk)),
		Offset:    0,
		Done:      false,
	})
	if err != nil {
		t.Fatalf("marshal first file write request: %v", err)
	}
	fm.HandleFileWrite(transport, protocol.Message{Data: firstRaw})

	select {
	case msg := <-messages:
		t.Fatalf("unexpected response before terminal upload marker: %+v", msg)
	default:
	}

	finalRaw, err := json.Marshal(protocol.FileWriteData{
		RequestID: "req-write-boundary",
		Path:      "boundary/output.txt",
		Data:      "",
		Offset:    int64(len(firstChunk)),
		Done:      true,
	})
	if err != nil {
		t.Fatalf("marshal terminal file write request: %v", err)
	}
	fm.HandleFileWrite(transport, protocol.Message{Data: finalRaw})

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileWritten, 2*time.Second)
	var written protocol.FileWrittenData
	if err := json.Unmarshal(msg.Data, &written); err != nil {
		t.Fatalf("decode file written payload: %v", err)
	}
	if written.Error != "" {
		t.Fatalf("expected successful write, got error %q", written.Error)
	}
	if written.BytesWritten != int64(len(firstChunk)) {
		t.Fatalf("unexpected bytes_written %d", written.BytesWritten)
	}

	data, err := os.ReadFile(filepath.Join(root, "boundary/output.txt"))
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if string(data) != firstChunk {
		t.Fatalf("unexpected persisted content length=%d", len(data))
	}

	tempFiles, err := filepath.Glob(filepath.Join(root, "boundary", ".lt-upload-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(tempFiles) != 0 {
		t.Fatalf("expected no leftover temp uploads, got %v", tempFiles)
	}

	if fm.HasPendingWrite("req-write-boundary") {
		t.Fatalf("expected pending writer cleanup after empty done marker")
	}
}

func TestFileManagerReadLargeFileEmitsChunkSequenceAndDoneMarker(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	content := strings.Repeat("r", files.FileChunkSize*2)
	filePath := filepath.Join(root, "large.bin")
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write large file fixture: %v", err)
	}

	fm := &files.Manager{
		BaseDir: root,
	}

	raw, err := json.Marshal(protocol.FileReadData{
		RequestID: "req-large-read",
		Path:      "large.bin",
	})
	if err != nil {
		t.Fatalf("marshal file read request: %v", err)
	}
	fm.HandleFileRead(transport, protocol.Message{Data: raw})

	var (
		payloads []protocol.FileDataPayload
		data     strings.Builder
	)
	deadline := time.After(2 * time.Second)
readLoop:
	for len(payloads) < 3 {
		select {
		case msg, ok := <-messages:
			if !ok {
				t.Fatal("transport closed before large file read completed")
			}
			if msg.Type != protocol.MsgFileData {
				continue
			}
			var payload protocol.FileDataPayload
			if err := json.Unmarshal(msg.Data, &payload); err != nil {
				t.Fatalf("decode file data payload: %v", err)
			}
			payloads = append(payloads, payload)
			decoded, err := base64.StdEncoding.DecodeString(payload.Data)
			if err != nil {
				t.Fatalf("decode file chunk: %v", err)
			}
			data.Write(decoded)
			if payload.Done {
				break readLoop
			}
		case <-deadline:
			t.Fatal("timed out waiting for large file read results")
		}
	}

	if len(payloads) != 3 {
		t.Fatalf("expected 3 read payloads (2 chunks + done marker), got %d", len(payloads))
	}
	if payloads[0].Done || payloads[1].Done {
		t.Fatalf("expected first two payloads to be non-terminal: %+v", payloads)
	}
	if payloads[0].Offset != 0 || payloads[1].Offset != int64(files.FileChunkSize) || payloads[2].Offset != int64(files.FileChunkSize*2) {
		t.Fatalf("unexpected offsets: %+v", payloads)
	}
	if !payloads[2].Done || payloads[2].Data != "" || payloads[2].Error != "" {
		t.Fatalf("unexpected terminal payload: %+v", payloads[2])
	}
	if data.String() != content {
		t.Fatalf("unexpected reconstructed content length=%d want=%d", len(data.String()), len(content))
	}
}
