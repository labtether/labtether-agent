package files

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestCopyPathRecursiveRejectsHugeDirectoryAndRemovesPartialDestination(t *testing.T) {
	baseDir := t.TempDir()
	srcDir := filepath.Join(baseDir, "src")
	dstDir := filepath.Join(baseDir, "dst")
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := range 300 {
		path := filepath.Join(srcDir, fmt.Sprintf("entry-%03d", index))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("create source entry %d: %v", index, err)
		}
	}

	limits := smallCopyTestLimits()
	limits.maxEntries = 50
	limits.readBatch = 7
	err := copyPathRecursiveWithLimits(context.Background(), srcDir, dstDir, limits)
	if !errors.Is(err, errCopyLimitExceeded) {
		t.Fatalf("copy error = %v, want errCopyLimitExceeded", err)
	}
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("copy error = %v, want explicit entry limit", err)
	}
	assertCopyDestinationAbsent(t, dstDir)
}

func TestCopyPathRecursiveRejectsCumulativeByteBudgetAndCleansCopiedFiles(t *testing.T) {
	baseDir := t.TempDir()
	srcDir := filepath.Join(baseDir, "src")
	dstDir := filepath.Join(baseDir, "dst")
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a-first"), []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b-second"), []byte("abcdefgh"), 0o600); err != nil {
		t.Fatal(err)
	}

	limits := smallCopyTestLimits()
	limits.maxBytes = 12
	limits.maxFileSize = 10
	err := copyPathRecursiveWithLimits(context.Background(), srcDir, dstDir, limits)
	if !errors.Is(err, errCopyLimitExceeded) {
		t.Fatalf("copy error = %v, want errCopyLimitExceeded", err)
	}
	if err == nil || !strings.Contains(err.Error(), "total data") {
		t.Fatalf("copy error = %v, want explicit total-byte limit", err)
	}
	assertCopyDestinationAbsent(t, dstDir)
}

func TestCopyPathRecursiveRejectsDepthBudgetAndCleansPartialTree(t *testing.T) {
	baseDir := t.TempDir()
	srcDir := filepath.Join(baseDir, "src")
	dstDir := filepath.Join(baseDir, "dst")
	deepDir := filepath.Join(srcDir, "one", "two", "three")
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "data"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	limits := smallCopyTestLimits()
	limits.maxDepth = 2
	err := copyPathRecursiveWithLimits(context.Background(), srcDir, dstDir, limits)
	if !errors.Is(err, errCopyLimitExceeded) {
		t.Fatalf("copy error = %v, want errCopyLimitExceeded", err)
	}
	if err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("copy error = %v, want explicit depth limit", err)
	}
	assertCopyDestinationAbsent(t, dstDir)
}

func TestCopyPathRecursiveRejectsOversizedSparseFileBeforeCreatingDestination(t *testing.T) {
	baseDir := t.TempDir()
	srcPath := filepath.Join(baseDir, "oversized")
	dstPath := filepath.Join(baseDir, "copy")
	file, err := os.OpenFile(srcPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxCopyFileSize + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = CopyPathRecursive(srcPath, dstPath)
	if !errors.Is(err, errCopyLimitExceeded) {
		t.Fatalf("copy error = %v, want errCopyLimitExceeded", err)
	}
	if err == nil || !strings.Contains(err.Error(), "file exceeds") {
		t.Fatalf("copy error = %v, want explicit file-size limit", err)
	}
	assertCopyDestinationAbsent(t, dstPath)
}

func TestCopyPathRecursiveContextHonorsCancellationWithoutDestination(t *testing.T) {
	baseDir := t.TempDir()
	srcPath := filepath.Join(baseDir, "source")
	dstPath := filepath.Join(baseDir, "destination")
	if err := os.WriteFile(srcPath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := CopyPathRecursiveContext(ctx, srcPath, dstPath)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("copy error = %v, want context.Canceled", err)
	}
	assertCopyDestinationAbsent(t, dstPath)
}

func TestCopyPathRecursiveEnforcesDeadline(t *testing.T) {
	baseDir := t.TempDir()
	srcPath := filepath.Join(baseDir, "source")
	dstPath := filepath.Join(baseDir, "destination")
	if err := os.WriteFile(srcPath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := CopyPathRecursiveContext(ctx, srcPath, dstPath)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("copy error = %v, want context.DeadlineExceeded", err)
	}
	assertCopyDestinationAbsent(t, dstPath)
}

func TestHandleFileCopyContextReturnsCancellationAndLeavesNoDestination(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "source"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	fm := &Manager{BaseDir: baseDir, HomeDir: baseDir, writers: make(map[string]*PendingWrite)}
	transport := &testFileTransport{}
	request := protocol.FileCopyData{
		RequestID: "canceled-copy",
		SrcPath:   "source",
		DstPath:   "destination",
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fm.HandleFileCopyContext(ctx, transport, protocol.Message{Type: protocol.MsgFileCopy, Data: data})

	result := lastFileResult(t, transport)
	if result.OK || !strings.Contains(result.Error, "copy canceled") {
		t.Fatalf("copy result = %+v, want cancellation failure", result)
	}
	assertCopyDestinationAbsent(t, filepath.Join(baseDir, "destination"))
}

func smallCopyTestLimits() copyLimits {
	return copyLimits{
		maxEntries:  1_000,
		maxBytes:    1_024,
		maxFileSize: 1_024,
		maxDepth:    16,
		maxDuration: time.Minute,
		readBatch:   8,
		bufferSize:  16,
	}
}

func assertCopyDestinationAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial copy destination remains at %q: %v", path, err)
	}
}
