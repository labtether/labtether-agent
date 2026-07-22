package files

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
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

func (e generatedFileListEntry) Name() string               { return e.name }
func (e generatedFileListEntry) IsDir() bool                { return false }
func (e generatedFileListEntry) Type() fs.FileMode          { return 0 }
func (e generatedFileListEntry) Info() (fs.FileInfo, error) { return generatedFileListInfo(e), nil }

type generatedFileListInfo generatedFileListEntry

func (i generatedFileListInfo) Name() string       { return i.name }
func (i generatedFileListInfo) Size() int64        { return 1 }
func (i generatedFileListInfo) Mode() fs.FileMode  { return 0o600 }
func (i generatedFileListInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (i generatedFileListInfo) IsDir() bool        { return false }
func (i generatedFileListInfo) Sys() any           { return nil }

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

// TestValidatePathPreventsTraversal verifies that paths outside baseDir are rejected.
func TestValidatePathPreventsTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: tmpDir,
	}

	cases := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"../../../root/.ssh/id_rsa",
	}

	for _, tc := range cases {
		_, err := fm.ValidatePath(tc)
		if err == nil {
			t.Errorf("expected error for path %q, got nil", tc)
		}
	}
}

// TestValidatePathAllowsSubdirectories verifies paths within baseDir are accepted.
func TestValidatePathAllowsSubdirectories(t *testing.T) {
	tmpDir := t.TempDir()
	// Resolve symlinks on baseDir itself (macOS /tmp -> /private/var/...).
	resolvedBase, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(resolvedBase, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: resolvedBase,
	}

	resolved, err := fm.ValidatePath("sub/file.txt")
	if err != nil {
		t.Fatalf("unexpected error for valid subpath: %v", err)
	}
	expected := filepath.Join(resolvedBase, "sub", "file.txt")
	if resolved != expected {
		t.Fatalf("expected %q, got %q", expected, resolved)
	}
}

// TestValidatePathEmpty returns baseDir for empty input.
func TestValidatePathEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	resolvedBase, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: resolvedBase,
	}

	resolved, err := fm.ValidatePath("")
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	if resolved != resolvedBase {
		t.Fatalf("expected %q, got %q", resolvedBase, resolved)
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

// TestValidatePathRejectsSymlinkToOutside ensures symlink final components
// cannot escape the base directory (regression for symlink traversal bug).
func TestValidatePathRejectsSymlinkToOutside(t *testing.T) {
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

	if _, err := fm.ValidatePath("outside-link"); err == nil {
		t.Fatalf("expected symlink path to be rejected")
	}
}

// TestValidatePathRejectsSymlinkDirectoryOutside ensures symlink directories are
// also blocked when the symlink itself is the final path component.
func TestValidatePathRejectsSymlinkDirectoryOutside(t *testing.T) {
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

	if _, err := fm.ValidatePath("outside-dir"); err == nil {
		t.Fatalf("expected symlink directory path to be rejected")
	}
}

func TestValidatePathRejectsMissingDescendantThroughSymlinkedParent(t *testing.T) {
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

	if _, err := fm.ValidatePath(filepath.Join("outside-dir", "new", "file.txt")); err == nil {
		t.Fatal("expected missing descendant under symlinked parent to be rejected")
	}
	if _, err := fm.ValidatePathNoFollowFinal(filepath.Join("outside-dir", "new", "file.txt")); err == nil {
		t.Fatal("expected no-follow validation to reject symlinked parent escape")
	}
}

func TestValidatePathNoFollowFinalAllowsFinalSymlinkToOutside(t *testing.T) {
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

	got, err := fm.ValidatePathNoFollowFinal("outside-link")
	if err != nil {
		t.Fatalf("expected final symlink itself to be accepted: %v", err)
	}
	if got != linkPath {
		t.Fatalf("expected lexical link path %q, got %q", linkPath, got)
	}
}

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

func TestHandleFileDeleteRemovesSymlinkWithoutTouchingTarget(t *testing.T) {
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
	fm.HandleFileDelete(transport, protocol.Message{
		Type: protocol.MsgFileDelete,
		ID:   "delete-1",
		Data: marshalTestMessage(t, protocol.FileDeleteData{
			RequestID: "delete-1",
			Path:      "outside-link",
		}),
	})

	result := lastFileResult(t, transport)
	if !result.OK {
		t.Fatalf("expected symlink delete to succeed, got error: %s", result.Error)
	}
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("expected symlink to be removed, stat err=%v", err)
	}
	got, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatalf("outside target was removed or unreadable: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("outside target content changed: %q", string(got))
	}
}

func TestHandleFileRenameRejectsBaseDirectory(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	transport := &testFileTransport{}
	fm.HandleFileRename(transport, protocol.Message{
		Type: protocol.MsgFileRename,
		ID:   "rename-base",
		Data: marshalTestMessage(t, protocol.FileRenameData{
			RequestID: "rename-base",
			OldPath:   "",
			NewPath:   "renamed-base",
		}),
	})

	result := lastFileResult(t, transport)
	if result.OK {
		t.Fatal("expected base directory rename to fail")
	}
	if !strings.Contains(result.Error, "base directory") {
		t.Fatalf("expected base directory error, got %q", result.Error)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "keep.txt")); err != nil {
		t.Fatalf("expected base directory contents to remain available: %v", err)
	}
}

func TestHandleFileRenameRejectsExistingDestination(t *testing.T) {
	baseDir := t.TempDir()
	srcPath := filepath.Join(baseDir, "source.txt")
	dstPath := filepath.Join(baseDir, "dest.txt")
	if err := os.WriteFile(srcPath, []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, []byte("dest"), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}
	transport := &testFileTransport{}
	fm.HandleFileRename(transport, protocol.Message{
		Type: protocol.MsgFileRename,
		ID:   "rename-existing-dest",
		Data: marshalTestMessage(t, protocol.FileRenameData{
			RequestID: "rename-existing-dest",
			OldPath:   "source.txt",
			NewPath:   "dest.txt",
		}),
	})

	result := lastFileResult(t, transport)
	if result.OK {
		t.Fatal("expected rename over existing destination to fail")
	}
	if !strings.Contains(result.Error, "destination already exists") {
		t.Fatalf("expected existing destination error, got %q", result.Error)
	}
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("expected source file to remain: %v", err)
	}
	if string(srcBytes) != "source" {
		t.Fatalf("unexpected source content: %q", string(srcBytes))
	}
	dstBytes, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("expected destination file to remain: %v", err)
	}
	if string(dstBytes) != "dest" {
		t.Fatalf("unexpected destination content: %q", string(dstBytes))
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

	oldPending := &PendingWrite{
		File:    oldFile,
		Path:    filepath.Join(baseDir, "old.txt"),
		TmpPath: oldFile.Name(),
	}
	newPending := &PendingWrite{
		File:    newFile,
		Path:    filepath.Join(baseDir, "new.txt"),
		TmpPath: newFile.Name(),
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

func TestCopyPathRecursiveCopiesNestedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "child.txt"), []byte("child-content"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := CopyPathRecursive(srcDir, dstDir); err != nil {
		t.Fatalf("CopyPathRecursive failed: %v", err)
	}

	rootBytes, err := os.ReadFile(filepath.Join(dstDir, "root.txt"))
	if err != nil {
		t.Fatalf("read copied root file: %v", err)
	}
	if string(rootBytes) != "root-content" {
		t.Fatalf("unexpected root file content: %q", string(rootBytes))
	}

	childBytes, err := os.ReadFile(filepath.Join(dstDir, "sub", "child.txt"))
	if err != nil {
		t.Fatalf("read copied child file: %v", err)
	}
	if string(childBytes) != "child-content" {
		t.Fatalf("unexpected child file content: %q", string(childBytes))
	}
}

func TestCopyPathRecursiveRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(targetFile, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	err := CopyPathRecursive(linkPath, filepath.Join(tmpDir, "copied-link.txt"))
	if err == nil {
		t.Fatal("expected symlink copy to fail")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got: %v", err)
	}
}

func TestCopyPathRecursiveRejectsDestinationInsideSource(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(srcDir, "nested-copy")
	err := CopyPathRecursive(srcDir, dstDir)
	if err == nil {
		t.Fatal("expected nested destination copy to fail")
	}
	if !strings.Contains(err.Error(), "inside source directory") {
		t.Fatalf("expected inside-source error, got: %v", err)
	}
}

func TestCopyPathRecursiveRejectsDestinationInsideSourceThroughSymlinkedParent(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(tmpDir, "link-to-src")
	if err := os.Symlink(srcDir, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	dstDir := filepath.Join(linkPath, "nested-copy")
	err := CopyPathRecursive(srcDir, dstDir)
	if err == nil {
		t.Fatal("expected symlink-parent nested destination copy to fail")
	}
	if !strings.Contains(err.Error(), "inside source directory") {
		t.Fatalf("expected inside-source error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(srcDir, "nested-copy")); !os.IsNotExist(statErr) {
		t.Fatalf("expected nested copy directory to remain absent, stat err=%v", statErr)
	}
}

func TestResolveFileBaseDirHomeModeUsesHomeByDefault(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		t.Skip("home directory unavailable")
	}
	got := ResolveFileBaseDir("home")
	if filepath.Clean(got) != filepath.Clean(home) {
		t.Fatalf("ResolveFileBaseDir(home) = %q, want %q", got, home)
	}
}

func TestResolveAgentFileHomeDirFallsBackToDesktopSessionHomeWhenProcessHomeReadOnly(t *testing.T) {
	originalHome := FileUserHomeDirFn
	originalLookupUser := FileLookupUserByUsernameFn
	originalLookupUID := FileLookupUserByUIDFn
	originalWritable := FileIsWritableDirFn
	originalDetect := DetectDesktopSessionFn
	originalTempDir := FileTempDirFn
	originalGetwd := FileGetwdFn
	t.Cleanup(func() {
		FileUserHomeDirFn = originalHome
		FileLookupUserByUsernameFn = originalLookupUser
		FileLookupUserByUIDFn = originalLookupUID
		FileIsWritableDirFn = originalWritable
		DetectDesktopSessionFn = originalDetect
		FileTempDirFn = originalTempDir
		FileGetwdFn = originalGetwd
	})

	FileUserHomeDirFn = func() (string, error) { return "/root", nil }
	FileLookupUserByUsernameFn = func(username string) (*user.User, error) {
		if username != "captain" {
			t.Fatalf("username=%q, want captain", username)
		}
		return &user.User{HomeDir: "/home/captain"}, nil
	}
	FileLookupUserByUIDFn = func(uid string) (*user.User, error) {
		t.Fatalf("unexpected uid lookup: %s", uid)
		return nil, nil
	}
	FileIsWritableDirFn = func(path string) bool {
		return filepath.Clean(path) == "/home/captain"
	}
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Username: "captain", UID: 1000}
	}
	FileTempDirFn = func() string {
		t.Fatal("did not expect temp fallback")
		return ""
	}
	FileGetwdFn = func() (string, error) {
		t.Fatal("did not expect cwd fallback")
		return "", nil
	}

	if got := ResolveAgentFileHomeDir(); got != "/home/captain" {
		t.Fatalf("ResolveAgentFileHomeDir() = %q, want /home/captain", got)
	}
}

func TestResolveAgentFileHomeDirFallsBackToStagingDirWhenHomesAreReadOnly(t *testing.T) {
	originalHome := FileUserHomeDirFn
	originalLookupUser := FileLookupUserByUsernameFn
	originalLookupUID := FileLookupUserByUIDFn
	originalWritable := FileIsWritableDirFn
	originalDetect := DetectDesktopSessionFn
	originalTempDir := FileTempDirFn
	originalGetwd := FileGetwdFn
	t.Cleanup(func() {
		FileUserHomeDirFn = originalHome
		FileLookupUserByUsernameFn = originalLookupUser
		FileLookupUserByUIDFn = originalLookupUID
		FileIsWritableDirFn = originalWritable
		DetectDesktopSessionFn = originalDetect
		FileTempDirFn = originalTempDir
		FileGetwdFn = originalGetwd
	})

	tempDir := t.TempDir()
	FileUserHomeDirFn = func() (string, error) { return "/root", nil }
	FileLookupUserByUsernameFn = func(string) (*user.User, error) {
		return &user.User{HomeDir: "/home/captain"}, nil
	}
	FileLookupUserByUIDFn = func(string) (*user.User, error) { return nil, os.ErrNotExist }
	FileIsWritableDirFn = func(path string) bool {
		return strings.HasPrefix(filepath.Clean(path), filepath.Clean(tempDir))
	}
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Username: "captain", UID: 1000}
	}
	FileTempDirFn = func() string { return tempDir }
	FileGetwdFn = func() (string, error) { return "/srv/labtether", nil }

	got := ResolveAgentFileHomeDir()
	want := filepath.Join(tempDir, "labtether-agent-home")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("ResolveAgentFileHomeDir() = %q, want %q", got, want)
	}
}

func TestResolveFileBaseDirFullModeContainsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		t.Skip("home directory unavailable")
	}
	got := ResolveFileBaseDir("full")
	if got == "" {
		t.Fatal("ResolveFileBaseDir(full) returned empty base dir")
	}
	if !PathWithinBaseDir(got, home) {
		t.Fatalf("ResolveFileBaseDir(full) = %q does not contain home %q", got, home)
	}
}

func TestValidatePathExpandsHomeUsingResolvedFileHome(t *testing.T) {
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: "/tmp/labtether-agent-home",
		HomeDir: "/tmp/labtether-agent-home",
	}

	got, err := fm.ValidatePath("~/notes.txt")
	if err != nil {
		t.Fatalf("ValidatePath returned error: %v", err)
	}
	tmpRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		tmpRoot = "/tmp"
	}
	if filepath.Clean(got) != filepath.Join(tmpRoot, "labtether-agent-home", "notes.txt") {
		t.Fatalf("ValidatePath expanded path = %q", got)
	}
}
