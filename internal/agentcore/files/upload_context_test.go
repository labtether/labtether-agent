package files

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestUploadOldSocketCannotRecreateOrAbortNewUpload(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 0)
	oldCtx, cancel := context.WithCancel(context.Background())
	chunk := protocol.FileWriteData{RequestID: "same-request", Path: "destination.txt", Data: base64.StdEncoding.EncodeToString([]byte("old"))}
	if _, err := fm.WriteChunkContext(oldCtx, chunk); err != nil {
		t.Fatal(err)
	}
	cancel()
	fm.CloseAll()
	assertNoUploadTemps(t, fm.BaseDir)
	chunk.Data = base64.StdEncoding.EncodeToString([]byte("new"))
	if _, err := fm.WriteChunkContext(context.Background(), chunk); err != nil {
		t.Fatal(err)
	}
	// Late data, malformed data, and EOF from the retired socket all leave the
	// new upload alone, even if a request ID is reused by a compatibility Hub.
	for _, old := range []protocol.FileWriteData{
		{RequestID: chunk.RequestID, Path: chunk.Path, Offset: 3, Data: "bGF0ZQ=="},
		{RequestID: chunk.RequestID, Path: chunk.Path, Data: "!"},
		{RequestID: chunk.RequestID, Path: chunk.Path, Offset: 3, Done: true},
	} {
		if _, err := fm.WriteChunkContext(oldCtx, old); !errors.Is(err, context.Canceled) {
			t.Fatalf("retired write: %v", err)
		}
	}
	if !fm.HasPendingWrite(chunk.RequestID) {
		t.Fatal("old request removed new upload")
	}
	if _, err := os.Stat(filepath.Join(fm.BaseDir, chunk.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old EOF committed destination: %v", err)
	}
	if _, err := fm.WriteChunkContext(context.Background(), protocol.FileWriteData{RequestID: chunk.RequestID, Path: chunk.Path, Offset: 3, Done: true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(fm.BaseDir, chunk.Path))
	if err != nil || string(data) != "new" {
		t.Fatalf("new destination=%q err=%v", data, err)
	}
	assertNoUploadTemps(t, fm.BaseDir)
	if _, err := fm.WriteChunkContext(oldCtx, protocol.FileWriteData{RequestID: "late-new", Path: "unexpected/destination.txt", Data: "eA==", Done: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("retired new request: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fm.BaseDir, "unexpected")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired request created directories: %v", err)
	}
}

func TestUploadCancellationAfterWritePreservesOriginalDestination(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 0)
	path := filepath.Join(fm.BaseDir, "destination.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The existing clock hook lets us cancel when real temporary file bytes
	// exist, before the final sync/rename. No fake filesystem or commit is used.
	fm.pendingWriteNow = func() time.Time {
		temps, _ := filepath.Glob(filepath.Join(fm.BaseDir, ".lt-upload-*"))
		for _, tmp := range temps {
			if data, err := os.ReadFile(tmp); err == nil && string(data) == "replacement" {
				cancel()
			}
		}
		return time.Now()
	}
	written, err := fm.WriteChunkContext(ctx, protocol.FileWriteData{RequestID: "cancel-commit", Path: "destination.txt", Data: base64.StdEncoding.EncodeToString([]byte("replacement")), Done: true})
	if !errors.Is(err, context.Canceled) || written != int64(len("replacement")) {
		t.Fatalf("write result=%d err=%v", written, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("destination changed=%q err=%v", data, err)
	}
	if fm.HasPendingWrite("cancel-commit") {
		t.Fatal("canceled commit retained writer")
	}
	assertNoUploadTemps(t, fm.BaseDir)
}

func TestUploadCloseAllInvalidatesPendingAllocation(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 0)
	var once sync.Once
	// Reconnect cleanup runs after the chunk enters its owner but before path
	// allocation. It also works for direct callers without a socket context.
	fm.pendingWriteNow = func() time.Time { once.Do(fm.CloseAll); return time.Now() }
	_, err := fm.WriteChunkContext(context.Background(), protocol.FileWriteData{RequestID: "retired-allocation", Path: "destination.txt", Data: "eA==", Done: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight allocation survived CloseAll: %v", err)
	}
	if fm.HasPendingWrite("retired-allocation") {
		t.Fatal("retired allocation retained writer")
	}
	if _, err := os.Stat(filepath.Join(fm.BaseDir, "destination.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired allocation committed: %v", err)
	}
	assertNoUploadTemps(t, fm.BaseDir)
}
