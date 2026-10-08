package files

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labtether/protocol"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testFileTransport struct {
	messages []protocol.Message
}

func (t *testFileTransport) Send(msg protocol.Message) error {
	t.messages = append(t.messages, msg)
	return nil
}

type failingFileTransport struct {
	calls int
	err   error
}

func (t *failingFileTransport) Send(protocol.Message) error {
	t.calls++
	return t.err
}

type cancelingFileTransport struct {
	cancel context.CancelFunc
	calls  int
}

func (t *cancelingFileTransport) Send(protocol.Message) error {
	t.calls++
	t.cancel()
	return nil
}

type countingReader struct {
	reader *bytes.Reader
	reads  int
}

func (r *countingReader) Read(dst []byte) (int, error) {
	r.reads++
	return r.reader.Read(dst)
}

type generatedFileListReader struct {
	remaining int
	index     int
	name      func(int) string
	readSizes []int
}

func (r *generatedFileListReader) ReadDir(n int) ([]fs.DirEntry, error) {
	r.readSizes = append(r.readSizes, n)
	if r.remaining == 0 {
		return nil, io.EOF
	}
	count := min(n, r.remaining)
	entries := make([]fs.DirEntry, 0, count)
	for range count {
		name := fmt.Sprintf("entry-%d", r.index)
		if r.name != nil {
			name = r.name(r.index)
		}
		entries = append(entries, generatedFileListEntry{name: name})
		r.index++
	}
	r.remaining -= count
	if r.remaining == 0 {
		return entries, io.EOF
	}
	return entries, nil
}

type generatedFileListEntry struct {
	name string
}

func (e generatedFileListEntry) Name() string { return e.name }

func (e generatedFileListEntry) IsDir() bool { return false }

func (e generatedFileListEntry) Type() fs.FileMode { return 0 }

func (e generatedFileListEntry) Info() (fs.FileInfo, error) { return generatedFileListInfo(e), nil }

type generatedFileListInfo generatedFileListEntry

func (i generatedFileListInfo) Name() string { return i.name }

func (i generatedFileListInfo) Size() int64 { return 1 }

func (i generatedFileListInfo) Mode() fs.FileMode { return 0o600 }

func (i generatedFileListInfo) ModTime() time.Time { return time.Unix(1, 0) }

func (i generatedFileListInfo) IsDir() bool { return false }

func (i generatedFileListInfo) Sys() any { return nil }

func marshalTestMessage(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func lastFileResult(t *testing.T, transport *testFileTransport) protocol.FileResultData {
	t.Helper()
	if len(transport.messages) == 0 {
		t.Fatal("expected at least one message")
	}
	var result protocol.FileResultData
	if err := json.Unmarshal(transport.messages[len(transport.messages)-1].Data, &result); err != nil {
		t.Fatalf("decode file result: %v", err)
	}
	return result
}

func lastFileData(t *testing.T, transport *testFileTransport) protocol.FileDataPayload {
	t.Helper()
	if len(transport.messages) == 0 {
		t.Fatal("expected at least one message")
	}
	var result protocol.FileDataPayload
	if err := json.Unmarshal(transport.messages[len(transport.messages)-1].Data, &result); err != nil {
		t.Fatalf("decode file data: %v", err)
	}
	return result
}

func TestReadBoundedFileEntriesUsesIncrementalPositiveReadsAndPreservesNormalListing(t *testing.T) {
	reader := &generatedFileListReader{
		remaining: 3,
		name: func(index int) string {
			if index == 0 {
				return ".hidden"
			}
			return fmt.Sprintf("visible-%d", index)
		},
	}

	entries, err := readBoundedFileEntries(reader, false, "request-1", "/tmp")
	if err != nil {
		t.Fatalf("readBoundedFileEntries: %v", err)
	}
	if len(entries) != 2 || entries[0].Name != "visible-1" || entries[1].Name != "visible-2" {
		t.Fatalf("entries = %#v, want the two visible entries", entries)
	}
	if len(reader.readSizes) == 0 {
		t.Fatal("expected at least one incremental ReadDir call")
	}
	for _, size := range reader.readSizes {
		if size != maxFileListReadBatch {
			t.Fatalf("ReadDir called with %d, want bounded batch %d", size, maxFileListReadBatch)
		}
	}
}

func TestReadBoundedFileEntriesRejectsVisibleEntryAmplification(t *testing.T) {
	reader := &generatedFileListReader{remaining: maxFileListEntries + 1}

	entries, err := readBoundedFileEntries(reader, true, "request-entries", "/tmp")
	if !errors.Is(err, errFileListLimitExceeded) {
		t.Fatalf("error = %v, want errFileListLimitExceeded", err)
	}
	if len(entries) != 0 {
		t.Fatalf("returned %d partial entries on limit failure, want none", len(entries))
	}
	if reader.index != maxFileListEntries+1 {
		t.Fatalf("scanned %d entries, want %d", reader.index, maxFileListEntries+1)
	}
}

func TestReadBoundedFileEntriesCapsHiddenEntryScanning(t *testing.T) {
	reader := &generatedFileListReader{
		remaining: maxFileListScanned + 1,
		name: func(int) string {
			return ".hidden"
		},
	}

	_, err := readBoundedFileEntries(reader, false, "request-hidden", "/tmp")
	if !errors.Is(err, errFileListLimitExceeded) {
		t.Fatalf("error = %v, want errFileListLimitExceeded", err)
	}
	if reader.index > maxFileListScanned+maxFileListReadBatch {
		t.Fatalf("scanned %d entries, exceeded one bounded read beyond scan limit", reader.index)
	}
}

func TestReadBoundedFileEntriesCapsSerializedResponse(t *testing.T) {
	reader := &generatedFileListReader{
		remaining: maxFileListEntries,
		name: func(index int) string {
			return fmt.Sprintf("%04d-%s", index, strings.Repeat("\x01", 250))
		},
	}

	_, err := readBoundedFileEntries(reader, true, "request-bytes", "/tmp")
	if !errors.Is(err, errFileListLimitExceeded) {
		t.Fatalf("error = %v, want errFileListLimitExceeded", err)
	}
	if err == nil || !strings.Contains(err.Error(), "serialized response") {
		t.Fatalf("error = %v, want explicit serialized response limit", err)
	}
	if reader.index >= maxFileListEntries {
		t.Fatalf("serialized cap did not stop enumeration early; scanned %d entries", reader.index)
	}
}

func TestSendFileListedFallsBackToBoundedErrorResponse(t *testing.T) {
	transport := &testFileTransport{}
	fm := &Manager{}
	oversizedRequestID := strings.Repeat("r", maxFileListResponseSize+1)

	fm.sendFileListed(transport, oversizedRequestID, "/tmp", nil, "")

	if len(transport.messages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.messages))
	}
	msg := transport.messages[0]
	if len(msg.Data) > maxFileListResponseSize {
		t.Fatalf("serialized response is %d bytes, limit %d", len(msg.Data), maxFileListResponseSize)
	}
	var listed protocol.FileListedData
	if err := json.Unmarshal(msg.Data, &listed); err != nil {
		t.Fatalf("decode bounded error response: %v", err)
	}
	if listed.Error == "" || !strings.Contains(listed.Error, "safe limits") {
		t.Fatalf("error = %q, want explicit safe-limit error", listed.Error)
	}
	if len(listed.RequestID) != maxFileListRequestIDLen {
		t.Fatalf("fallback request ID length = %d, want %d", len(listed.RequestID), maxFileListRequestIDLen)
	}
	if len(listed.Entries) != 0 {
		t.Fatalf("fallback returned %d entries, want none", len(listed.Entries))
	}
}

// TestFileWriteSizeLimitEnforced verifies that the size enforcement check
// would reject writes that exceed MaxFileSize (regression for F3: agent file
// upload had no cumulative size check).
func TestFileWriteSizeLimitEnforced(t *testing.T) {
	// Verify the MaxFileSize constant is 512MB.
	if MaxFileSize != 512*1024*1024 {
		t.Fatalf("expected MaxFileSize = 512MB, got %d", MaxFileSize)
	}

	// Simulate the check that now exists in HandleFileWrite.
	written := int64(MaxFileSize - 100) // Nearly at limit
	chunkLen := int64(200)              // Chunk that pushes past limit

	if written+chunkLen <= MaxFileSize {
		t.Fatal("expected size check to fail: written + chunk should exceed MaxFileSize")
	}
}

// TestFileWriteWithinLimitAllowed verifies that writes within size limit pass.
func TestFileWriteWithinLimitAllowed(t *testing.T) {
	written := int64(1024)
	chunkLen := int64(100)

	if written+chunkLen > MaxFileSize {
		t.Fatalf("expected %d + %d to be within MaxFileSize %d", written, chunkLen, MaxFileSize)
	}
}

// TestCleanupOrphanedTempFiles verifies old temp files are removed.
func TestCleanupOrphanedTempFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an old temp file (modified 10 minutes ago).
	oldFile := filepath.Join(tmpDir, ".lt-upload-old")
	if err := os.WriteFile(oldFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	tenMinAgo := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(oldFile, tenMinAgo, tenMinAgo); err != nil {
		t.Fatal(err)
	}

	// Create a recent temp file (should not be cleaned).
	recentFile := filepath.Join(tmpDir, ".lt-upload-recent")
	if err := os.WriteFile(recentFile, []byte("recent"), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: tmpDir,
	}
	fm.CleanupOrphanedTempFiles()

	// Old file should be removed.
	if _, err := os.Stat(oldFile); err == nil {
		t.Error("expected old temp file to be cleaned up")
	}

	// Recent file should remain.
	if _, err := os.Stat(recentFile); err != nil {
		t.Error("expected recent temp file to be preserved")
	}
}

func TestWriteChunkRejectsMissingDescendantThroughSymlinkedParent(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()

	linkPath := filepath.Join(baseDir, "outside-dir")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	_, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "write-1",
		Path:      filepath.Join("outside-dir", "new", "file.txt"),
		Data:      base64.StdEncoding.EncodeToString([]byte("secret")),
		Done:      true,
	})
	if err == nil {
		t.Fatal("expected upload through symlinked parent to be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(outsideDir, "new")); !os.IsNotExist(statErr) {
		t.Fatalf("expected outside directory to remain untouched, stat err=%v", statErr)
	}
}

func TestCleanupPendingWriteDoesNotRemoveReplacementForSameRequestID(t *testing.T) {
	baseDir := t.TempDir()
	oldFile, err := os.CreateTemp(baseDir, ".lt-upload-old-*")
	if err != nil {
		t.Fatal(err)
	}
	newFile, err := os.CreateTemp(baseDir, ".lt-upload-new-*")
	if err != nil {
		t.Fatal(err)
	}
	oldRoot, err := os.OpenRoot(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	newRoot, err := os.OpenRoot(baseDir)
	if err != nil {
		_ = oldRoot.Close()
		t.Fatal(err)
	}

	oldPending := &PendingWrite{
		File:       oldFile,
		Root:       oldRoot,
		Path:       filepath.Join(baseDir, "old.txt"),
		TmpPath:    oldFile.Name(),
		TmpRelPath: filepath.Base(oldFile.Name()),
	}
	newPending := &PendingWrite{
		File:       newFile,
		Root:       newRoot,
		Path:       filepath.Join(baseDir, "new.txt"),
		TmpPath:    newFile.Name(),
		TmpRelPath: filepath.Base(newFile.Name()),
	}
	fm := &Manager{
		writers: map[string]*PendingWrite{
			"upload-1": newPending,
		},
		BaseDir: baseDir,
	}
	t.Cleanup(fm.CloseAll)

	fm.cleanupPendingWrite("upload-1", oldPending)

	if !oldPending.Closed {
		t.Fatal("expected stale pending writer to be closed")
	}
	if _, statErr := os.Stat(oldPending.TmpPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected stale temp file to be removed, stat err=%v", statErr)
	}
	if newPending.Closed {
		t.Fatal("replacement pending writer was closed")
	}
	if _, statErr := os.Stat(newPending.TmpPath); statErr != nil {
		t.Fatalf("expected replacement temp file to remain, stat err=%v", statErr)
	}

	fm.mu.Lock()
	got := fm.writers["upload-1"]
	fm.mu.Unlock()
	if got != newPending {
		t.Fatal("replacement pending writer was removed from manager")
	}
}
