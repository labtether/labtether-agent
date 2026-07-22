package agentcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
)

type gatedFileReadTransport struct {
	firstSendStarted chan struct{}
	releaseFirstSend chan struct{}

	mu    sync.Mutex
	calls int
}

func (t *gatedFileReadTransport) Send(protocol.Message) error {
	t.mu.Lock()
	t.calls++
	call := t.calls
	t.mu.Unlock()

	if call == 1 {
		close(t.firstSendStarted)
		<-t.releaseFirstSend
		return errors.New("transport closed")
	}
	return nil
}

func (t *gatedFileReadTransport) sendCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

func TestFileReadSendFailureReleasesHandlerSemaphore(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "large.bin"), bytes.Repeat([]byte("x"), files.FileChunkSize*2), 0o600); err != nil {
		t.Fatalf("write large fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "small.txt"), []byte("still responsive"), 0o600); err != nil {
		t.Fatalf("write small fixture: %v", err)
	}

	fileMgr := &files.Manager{BaseDir: baseDir}
	transport := &gatedFileReadTransport{
		firstSendStarted: make(chan struct{}),
		releaseFirstSend: make(chan struct{}),
	}
	encode := func(requestID, path string) protocol.Message {
		t.Helper()
		data, err := json.Marshal(protocol.FileReadData{RequestID: requestID, Path: path})
		if err != nil {
			t.Fatalf("marshal file read: %v", err)
		}
		return protocol.Message{Type: protocol.MsgFileRead, ID: requestID, Data: data}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sem := make(chan struct{}, 1)
	var handlerWG sync.WaitGroup
	if !startFileReadHandler(ctx, transport, fileMgr, encode("first", "large.bin"), sem, &handlerWG) {
		t.Fatal("first handler was not started")
	}

	select {
	case <-transport.firstSendStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first handler did not reach transport send")
	}
	if got := len(sem); got != 1 {
		t.Fatalf("semaphore occupancy = %d, want 1 while first send is blocked", got)
	}

	secondStarted := make(chan bool, 1)
	go func() {
		secondStarted <- startFileReadHandler(ctx, transport, fileMgr, encode("second", "small.txt"), sem, &handlerWG)
	}()
	close(transport.releaseFirstSend)

	select {
	case started := <-secondStarted:
		if !started {
			t.Fatal("second handler was not started")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second handler remained blocked after first send failed")
	}

	drained := make(chan struct{})
	go func() {
		handlerWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("file read handlers did not drain")
	}
	if got := len(sem); got != 0 {
		t.Fatalf("semaphore occupancy = %d after handlers drained, want 0", got)
	}
	if got := transport.sendCalls(); got < 2 {
		t.Fatalf("transport sends = %d, want follow-up handler to send", got)
	}
}
