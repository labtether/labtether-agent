package files

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestWriteChunkRejectsEmptyNonFinalRequestWithoutOccupyingSlot(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 0)

	written, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "empty-non-final",
		Path:      "empty.txt",
		Done:      false,
	})
	if err == nil || !strings.Contains(err.Error(), "empty upload chunk must be final") {
		t.Fatalf("WriteChunk error = %v, want empty non-final rejection", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0", written)
	}
	if fm.HasPendingWrite("empty-non-final") {
		t.Fatal("empty non-final request occupied an upload slot")
	}
	assertNoUploadTemps(t, fm.BaseDir)

	// A terminal empty chunk is the valid representation of an empty file.
	written, err = fm.WriteChunk(protocol.FileWriteData{
		RequestID: "empty-final",
		Path:      "empty.txt",
		Done:      true,
	})
	if err != nil {
		t.Fatalf("terminal empty WriteChunk: %v", err)
	}
	if written != 0 {
		t.Fatalf("empty file written = %d, want 0", written)
	}
	info, err := os.Stat(filepath.Join(fm.BaseDir, "empty.txt"))
	if err != nil {
		t.Fatalf("stat empty file: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("empty file size = %d, want 0", info.Size())
	}
}

func TestWriteChunkRejectsOversizedChunkAndRequestIDBeforeAllocating(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 0)

	oversizedEncodedChunk := strings.Repeat("A", base64.StdEncoding.EncodedLen(FileChunkSize)+1)
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "oversized-chunk",
		Path:      "large.txt",
		Data:      oversizedEncodedChunk,
	}); err == nil || !strings.Contains(err.Error(), "upload chunk exceeds") {
		t.Fatalf("oversized chunk error = %v", err)
	}
	if fm.HasPendingWrite("oversized-chunk") {
		t.Fatal("oversized chunk occupied an upload slot")
	}

	oversizedID := strings.Repeat("r", maxFileWriteRequestIDLen+1)
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: oversizedID,
		Path:      "id.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("x")),
	}); err == nil || !strings.Contains(err.Error(), "request_id exceeds") {
		t.Fatalf("oversized request ID error = %v", err)
	}
	if got := pendingUploadCount(fm); got != 0 {
		t.Fatalf("pending upload count = %d, want 0", got)
	}
	assertNoUploadTemps(t, fm.BaseDir)
}

func TestWriteChunkReclaimsAllExpiredSlotsBeforeEnforcingSessionBound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ttl := time.Minute
	fm := newUploadLimitTestManager(t, func() time.Time { return now }, ttl)
	chunk := base64.StdEncoding.EncodeToString([]byte("x"))

	for index := range maxWritePending {
		requestID := fmt.Sprintf("abandoned-%d", index)
		if _, err := fm.WriteChunk(protocol.FileWriteData{
			RequestID: requestID,
			Path:      fmt.Sprintf("abandoned-%d.txt", index),
			Data:      chunk,
		}); err != nil {
			t.Fatalf("seed pending upload %d: %v", index, err)
		}
	}
	if got := pendingUploadCount(fm); got != maxWritePending {
		t.Fatalf("pending upload count = %d, want %d", got, maxWritePending)
	}
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "blocked-before-expiry",
		Path:      "blocked.txt",
		Data:      chunk,
		Done:      true,
	}); err == nil || !strings.Contains(err.Error(), "too many concurrent uploads") {
		t.Fatalf("slot-bound error = %v, want concurrent upload limit", err)
	}

	now = now.Add(ttl + time.Second)
	written, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "after-expiry",
		Path:      "after-expiry.txt",
		Data:      chunk,
		Done:      true,
	})
	if err != nil {
		t.Fatalf("upload after expiry: %v", err)
	}
	if written != 1 {
		t.Fatalf("written after expiry = %d, want 1", written)
	}
	if got := pendingUploadCount(fm); got != 0 {
		t.Fatalf("pending upload count after expiry = %d, want 0", got)
	}
	for index := range maxWritePending {
		if fm.HasPendingWrite(fmt.Sprintf("abandoned-%d", index)) {
			t.Fatalf("abandoned upload %d was not reclaimed", index)
		}
	}
	assertNoUploadTemps(t, fm.BaseDir)
}

func TestPendingWriteActivityRefreshPreservesValidChunking(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ttl := time.Minute
	fm := newUploadLimitTestManager(t, func() time.Time { return now }, ttl)

	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "active",
		Path:      "active.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("a")),
	}); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	now = now.Add(30 * time.Second)
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "active",
		Path:      "active.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("b")),
		Offset:    1,
	}); err != nil {
		t.Fatalf("second chunk: %v", err)
	}

	// Seventy seconds after creation is beyond the original deadline, but only
	// forty seconds after the last successful chunk.
	now = now.Add(40 * time.Second)
	if expired := fm.cleanupExpiredPendingWrites(now); expired != 0 {
		t.Fatalf("expired %d active uploads, want 0", expired)
	}
	if !fm.HasPendingWrite("active") {
		t.Fatal("active upload was removed despite recent progress")
	}

	if written, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "active",
		Path:      "active.txt",
		Offset:    2,
		Done:      true,
	}); err != nil || written != 2 {
		t.Fatalf("terminal chunk = (%d, %v), want (2, nil)", written, err)
	}
	content, err := os.ReadFile(filepath.Join(fm.BaseDir, "active.txt"))
	if err != nil {
		t.Fatalf("read completed upload: %v", err)
	}
	if string(content) != "ab" {
		t.Fatalf("completed upload = %q, want %q", content, "ab")
	}
}

func TestPendingWriteExpiryWaitsForActiveWriterLock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ttl := time.Minute
	fm := newUploadLimitTestManager(t, func() time.Time { return now }, ttl)
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "locked",
		Path:      "locked.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("x")),
	}); err != nil {
		t.Fatalf("seed upload: %v", err)
	}

	fm.mu.Lock()
	pw := fm.writers["locked"]
	fm.mu.Unlock()
	if pw == nil {
		t.Fatal("pending writer not found")
	}

	pw.mu.Lock()
	expiryTime := now.Add(ttl + time.Second)
	started := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		close(started)
		done <- fm.cleanupExpiredPendingWrites(expiryTime)
	}()
	<-started
	select {
	case <-done:
		pw.mu.Unlock()
		t.Fatal("expiry completed while the active writer lock was held")
	case <-time.After(25 * time.Millisecond):
	}

	// Simulate the active chunk completing at the same time as the expiry
	// sweep. The sweep must observe this refreshed timestamp after acquiring
	// the writer lock and leave the upload open.
	pw.lastActivity = expiryTime
	pw.mu.Unlock()
	if expired := <-done; expired != 0 {
		t.Fatalf("expired %d uploads after active progress, want 0", expired)
	}
	if !fm.HasPendingWrite("locked") {
		t.Fatal("expiry closed the active writer")
	}
}

func TestPendingWriteTimerExpiresWithoutAnotherRequest(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 25*time.Millisecond)
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "timer",
		Path:      "timer.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("x")),
	}); err != nil {
		t.Fatalf("seed upload: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for fm.HasPendingWrite("timer") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if fm.HasPendingWrite("timer") {
		t.Fatal("idle timer did not expire abandoned upload")
	}
	assertNoUploadTemps(t, fm.BaseDir)
}

func newUploadLimitTestManager(t *testing.T, now func() time.Time, ttl time.Duration) *Manager {
	t.Helper()
	baseDir := t.TempDir()
	fm := &Manager{
		writers:             make(map[string]*PendingWrite),
		pendingWriteNow:     now,
		pendingWriteIdleTTL: ttl,
		BaseDir:             baseDir,
		HomeDir:             baseDir,
	}
	t.Cleanup(fm.CloseAll)
	return fm
}

func pendingUploadCount(fm *Manager) int {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return len(fm.writers)
}

func assertNoUploadTemps(t *testing.T, baseDir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(baseDir, ".lt-upload-*"))
	if err != nil {
		t.Fatalf("glob upload temps: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("orphan upload temp files remain: %v", matches)
	}
}

func TestCleanupExpiredPendingWritesIsIdempotent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fm := newUploadLimitTestManager(t, func() time.Time { return now }, time.Minute)
	if _, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "idempotent",
		Path:      "idempotent.txt",
		Data:      base64.StdEncoding.EncodeToString([]byte("x")),
	}); err != nil {
		t.Fatalf("seed upload: %v", err)
	}

	now = now.Add(2 * time.Minute)
	if expired := fm.cleanupExpiredPendingWrites(now); expired != 1 {
		t.Fatalf("first cleanup expired %d uploads, want 1", expired)
	}
	if expired := fm.cleanupExpiredPendingWrites(now); expired != 0 {
		t.Fatalf("second cleanup expired %d uploads, want 0", expired)
	}
	if _, err := os.Stat(filepath.Join(fm.BaseDir, "idempotent.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination unexpectedly exists, stat error = %v", err)
	}
	assertNoUploadTemps(t, fm.BaseDir)
}
