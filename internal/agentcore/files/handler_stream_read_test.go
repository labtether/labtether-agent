package files

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/labtether/protocol"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandleFileReadRejectsSymlinkToOutside(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(baseDir, "outside-link")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	transport := &testFileTransport{}
	fm.HandleFileRead(transport, protocol.Message{
		Type: protocol.MsgFileRead,
		ID:   "read-1",
		Data: marshalTestMessage(t, protocol.FileReadData{
			RequestID: "read-1",
			Path:      "outside-link",
		}),
	})

	result := lastFileData(t, transport)
	if result.Error == "" {
		t.Fatal("expected read through symlink escape to fail")
	}
	if result.Data != "" {
		t.Fatalf("expected no data for rejected read, got %q", result.Data)
	}
}

func TestStreamFileReadEnforcesCumulativeLimitIndependentOfStat(t *testing.T) {
	fm := &Manager{}
	transport := &testFileTransport{}
	limit := int64(FileChunkSize + 10)
	reader := bytes.NewReader(bytes.Repeat([]byte("x"), int(limit+1)))

	offset, err := fm.streamFileRead(context.Background(), transport, "bounded-read", reader, limit)
	if !errors.Is(err, errFileReadLimitExceeded) {
		t.Fatalf("streamFileRead error = %v, want cumulative limit error", err)
	}
	if offset != FileChunkSize {
		t.Fatalf("offset = %d, want only the first bounded chunk %d", offset, FileChunkSize)
	}
	var sentBytes int
	for _, msg := range transport.messages {
		var payload protocol.FileDataPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload.Data)
		if err != nil {
			t.Fatalf("decode chunk: %v", err)
		}
		sentBytes += len(decoded)
		if payload.Done {
			t.Fatal("oversized stream must not be marked successfully complete")
		}
	}
	if int64(sentBytes) > limit {
		t.Fatalf("stream sent %d bytes beyond cumulative limit %d", sentBytes, limit)
	}
}

func TestStreamFileReadStopsOnContextCancellation(t *testing.T) {
	fm := &Manager{}
	ctx, cancel := context.WithCancel(context.Background())
	transport := &cancelingFileTransport{cancel: cancel}
	reader := &countingReader{reader: bytes.NewReader(bytes.Repeat([]byte("x"), FileChunkSize*3))}

	offset, err := fm.streamFileRead(ctx, transport, "canceled-read", reader, MaxFileSize)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("streamFileRead error = %v, want context cancellation", err)
	}
	if offset != FileChunkSize {
		t.Fatalf("offset = %d, want one sent chunk", offset)
	}
	if transport.calls != 1 || reader.reads != 1 {
		t.Fatalf("stream continued after cancellation: sends=%d reads=%d", transport.calls, reader.reads)
	}
}

func TestHandleFileReadStopsOnSendFailureWithoutHandlerStall(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "large.bin"), bytes.Repeat([]byte("x"), FileChunkSize*3), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "small.txt"), []byte("still responsive"), 0o600); err != nil {
		t.Fatalf("write follow-up fixture: %v", err)
	}
	fm := &Manager{BaseDir: baseDir}
	transport := &failingFileTransport{err: errors.New("transport closed")}
	request := protocol.Message{Data: marshalTestMessage(t, protocol.FileReadData{
		RequestID: "failed-send",
		Path:      "large.bin",
	})}

	done := make(chan struct{})
	go func() {
		fm.HandleFileRead(transport, request)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("file read handler stalled after transport send failure")
	}
	if transport.calls != 1 {
		t.Fatalf("send calls = %d, want immediate stop after first failure", transport.calls)
	}

	// A subsequent handler on the same manager must still run, demonstrating
	// that the failed stream did not retain manager/handler resources.
	followUp := &testFileTransport{}
	fm.HandleFileRead(followUp, protocol.Message{Data: marshalTestMessage(t, protocol.FileReadData{
		RequestID: "follow-up",
		Path:      "small.txt",
	})})
	result := lastFileData(t, followUp)
	if result.Error != "" || !result.Done {
		t.Fatalf("follow-up handler did not complete: %+v", result)
	}
}
