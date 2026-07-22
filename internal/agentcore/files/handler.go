package files

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/labtether/protocol"
)

const (
	FileChunkSize            = 64 * 1024         // 64KB per chunk
	MaxFileSize              = 512 * 1024 * 1024 // 512MB max file transfer
	maxFileListEntries       = 5000
	maxFileListScanned       = 20000
	maxFileListReadBatch     = 256
	maxFileListResponseSize  = 4 * 1024 * 1024
	maxFileListRequestIDLen  = 256
	maxWritePending          = 64
	maxFileWriteRequestIDLen = 256
	pendingWriteIdleTTL      = 5 * time.Minute
	orphanCleanupScanBudget  = 2 * time.Second
	orphanCleanupMaxEntries  = 20000
)

var (
	errFileListLimitExceeded = errors.New("directory listing exceeds safe limits")
	errFileReadLimitExceeded = errors.New("file too large")
	errFileReadSendFailed    = errors.New("file read transport send failed")
)

type fileListDirReader interface {
	ReadDir(n int) ([]fs.DirEntry, error)
}

// MessageSender abstracts the agent-to-hub send capability so this package
// does not depend on the concrete wsTransport type in the parent agentcore package.
type MessageSender interface {
	Send(msg protocol.Message) error
}

// Manager manages file operations on the agent.
type Manager struct {
	mu                  sync.Mutex
	writers             map[string]*PendingWrite // request_id -> pending write
	pendingWriteNow     func() time.Time
	pendingWriteIdleTTL time.Duration
	BaseDir             string // restricted base directory (empty = home dir)
	HomeDir             string // resolved home directory for "~" expansion
}

// PendingWrite tracks an in-progress file upload.
type PendingWrite struct {
	mu           sync.Mutex
	File         *os.File
	Root         *os.Root
	Path         string
	RelPath      string
	TmpPath      string
	TmpRelPath   string
	Written      int64
	Closed       bool
	lastActivity time.Time
	idleTimer    *time.Timer
}

// NewManager creates a new file Manager with the given file root mode.
func NewManager(fileRootMode string) *Manager {
	homeDir := ResolveAgentFileHomeDir()
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: ResolveFileBaseDirWithHome(fileRootMode, homeDir),
		HomeDir: homeDir,
	}
	// Evaluate the immutable startup path before launching cleanup so callers
	// that replace BaseDir for an isolated test/session cannot race the goroutine.
	go fm.cleanupOrphanedTempFiles(fm.BaseDir)
	return fm
}

// HandleFileList handles a file list request from the hub.
func (fm *Manager) HandleFileList(transport MessageSender, msg protocol.Message) {
	var req protocol.FileListData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid list request: %v", err)
		return
	}

	root, relPath, dirPath, err := fm.OpenRootPath(req.Path)
	if err != nil {
		fm.sendFileListed(transport, req.RequestID, req.Path, nil, err.Error())
		return
	}
	defer root.Close()

	dir, err := root.Open(relPath)
	if err != nil {
		fm.sendFileListed(transport, req.RequestID, dirPath, nil, err.Error())
		return
	}
	defer dir.Close()
	fileEntries, err := readBoundedFileEntries(dir, req.ShowHidden, req.RequestID, dirPath)
	if err != nil {
		fm.sendFileListed(transport, req.RequestID, dirPath, nil, err.Error())
		return
	}

	fm.sendFileListed(transport, req.RequestID, dirPath, fileEntries, "")
}

func readBoundedFileEntries(dir fileListDirReader, showHidden bool, requestID, path string) ([]protocol.FileEntry, error) {
	emptyPayload, err := json.Marshal(protocol.FileListedData{
		RequestID: requestID,
		Path:      path,
		Entries:   []protocol.FileEntry{},
	})
	if err != nil {
		return nil, err
	}
	if len(emptyPayload) > maxFileListResponseSize {
		return nil, fmt.Errorf("%w: response metadata exceeds %d bytes", errFileListLimitExceeded, maxFileListResponseSize)
	}

	entries := make([]protocol.FileEntry, 0, min(maxFileListEntries, maxFileListReadBatch))
	serializedSize := len(emptyPayload)
	scanned := 0
	for {
		batch, readErr := dir.ReadDir(maxFileListReadBatch)
		for _, entry := range batch {
			scanned++
			if scanned > maxFileListScanned {
				return nil, fmt.Errorf("%w: more than %d directory entries", errFileListLimitExceeded, maxFileListScanned)
			}
			if !showHidden && strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			if len(entries) >= maxFileListEntries {
				return nil, fmt.Errorf("%w: more than %d visible entries", errFileListLimitExceeded, maxFileListEntries)
			}

			fileEntry := protocol.FileEntry{
				Name:    entry.Name(),
				Size:    info.Size(),
				Mode:    info.Mode().String(),
				ModTime: info.ModTime().UTC().Format(time.RFC3339),
				IsDir:   entry.IsDir(),
			}
			encodedEntry, marshalErr := json.Marshal(fileEntry)
			if marshalErr != nil {
				return nil, marshalErr
			}
			nextSize := serializedSize + len(encodedEntry)
			if len(entries) == 0 {
				// Replace the empty array's two brackets with the first entry.
				nextSize -= 2
			} else {
				// Account for the comma between array entries.
				nextSize++
			}
			if nextSize > maxFileListResponseSize {
				return nil, fmt.Errorf("%w: serialized response exceeds %d bytes", errFileListLimitExceeded, maxFileListResponseSize)
			}
			entries = append(entries, fileEntry)
			serializedSize = nextSize
		}

		switch {
		case errors.Is(readErr, io.EOF):
			return entries, nil
		case readErr != nil:
			return nil, readErr
		case len(batch) == 0:
			return nil, io.ErrNoProgress
		}
	}
}

func (fm *Manager) sendFileListed(transport MessageSender, requestID, path string, entries []protocol.FileEntry, errMsg string) {
	if entries == nil {
		entries = []protocol.FileEntry{}
	}
	data, err := json.Marshal(protocol.FileListedData{
		RequestID: requestID,
		Path:      path,
		Entries:   entries,
		Error:     errMsg,
	})
	if err != nil {
		log.Printf("file: failed to marshal list response: %v", err)
		return
	}
	if len(data) > maxFileListResponseSize {
		if len(requestID) > maxFileListRequestIDLen {
			requestID = requestID[:maxFileListRequestIDLen]
		}
		data, err = json.Marshal(protocol.FileListedData{
			RequestID: requestID,
			Path:      "",
			Entries:   []protocol.FileEntry{},
			Error:     fmt.Sprintf("%s: serialized response exceeds %d bytes", errFileListLimitExceeded, maxFileListResponseSize),
		})
		if err != nil {
			log.Printf("file: failed to marshal bounded list error response: %v", err)
			return
		}
	}
	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgFileListed,
		ID:   requestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("file: failed to send list response request_id=%s: %v", requestID, sendErr)
	}
}

// HandleFileRead handles a file read request from the hub.
func (fm *Manager) HandleFileRead(transport MessageSender, msg protocol.Message) {
	fm.HandleFileReadContext(context.Background(), transport, msg)
}

// HandleFileReadContext handles a file read request and stops streaming when
// the caller's lifecycle ends. The non-context wrapper is retained for direct
// callers outside the receive loop.
func (fm *Manager) HandleFileReadContext(ctx context.Context, transport MessageSender, msg protocol.Message) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return
	}

	var req protocol.FileReadData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid read request: %v", err)
		return
	}

	root, relPath, _, err := fm.OpenRootPath(req.Path)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, err.Error())
		return
	}
	defer root.Close()
	if ctx.Err() != nil {
		return
	}

	f, err := openRootFileForRead(root, relPath)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, err.Error())
		return
	}
	defer f.Close()
	if ctx.Err() != nil {
		return
	}
	info, err := f.Stat()
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, err.Error())
		return
	}
	if info.IsDir() {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, "cannot read a directory")
		return
	}
	if !info.Mode().IsRegular() {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, "cannot read a non-regular file")
		return
	}
	if info.Size() > MaxFileSize {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, errFileReadLimitExceeded.Error())
		return
	}

	offset, streamErr := fm.streamFileRead(ctx, transport, req.RequestID, f, MaxFileSize)
	if streamErr != nil {
		switch {
		case errors.Is(streamErr, context.Canceled), errors.Is(streamErr, context.DeadlineExceeded):
			log.Printf("file: read canceled request_id=%s: %v", req.RequestID, streamErr)
		case errors.Is(streamErr, errFileReadSendFailed):
			log.Printf("file: read transport failed request_id=%s: %v", req.RequestID, streamErr)
		default:
			if sendErr := fm.sendFileData(transport, req.RequestID, "", offset, true, streamErr.Error()); sendErr != nil {
				log.Printf("file: failed to send read error request_id=%s: %v", req.RequestID, sendErr)
			}
		}
	}
}

func (fm *Manager) streamFileRead(ctx context.Context, transport MessageSender, requestID string, reader io.Reader, maxBytes int64) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxBytes < 0 {
		return 0, errFileReadLimitExceeded
	}
	buf := make([]byte, FileChunkSize)
	var offset int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		remaining := maxBytes - offset
		readSize := int64(len(buf))
		if remaining < readSize {
			readSize = remaining + 1
		}
		if readSize < 1 {
			readSize = 1
		}

		n, readErr := reader.Read(buf[:int(readSize)])
		if n < 0 || n > int(readSize) {
			return offset, fmt.Errorf("invalid read count %d", n)
		}
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		if n > 0 {
			emptyReads = 0
			if int64(n) > remaining {
				return offset, errFileReadLimitExceeded
			}
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			done := readErr == io.EOF
			if sendErr := fm.sendFileData(transport, requestID, encoded, offset, done, ""); sendErr != nil {
				return offset, fmt.Errorf("%w: %v", errFileReadSendFailed, sendErr)
			}
			offset += int64(n)
			if done {
				return offset, nil
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return offset, io.ErrNoProgress
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return offset, readErr
			}
			// EOF with n==0 -- send final empty done marker.
			if sendErr := fm.sendFileData(transport, requestID, "", offset, true, ""); sendErr != nil {
				return offset, fmt.Errorf("%w: %v", errFileReadSendFailed, sendErr)
			}
			return offset, nil
		}
	}
}

func (fm *Manager) sendFileData(transport MessageSender, requestID, data string, offset int64, done bool, errMsg string) error {
	payload, err := json.Marshal(protocol.FileDataPayload{
		RequestID: requestID,
		Data:      data,
		Offset:    offset,
		Done:      done,
		Error:     errMsg,
	})
	if err != nil {
		return err
	}
	return transport.Send(protocol.Message{
		Type: protocol.MsgFileData,
		ID:   requestID,
		Data: payload,
	})
}

// SendFileWritten sends a file-written acknowledgement to the hub.
func (fm *Manager) SendFileWritten(transport MessageSender, requestID string, bytesWritten int64, errMsg string) {
	data, _ := json.Marshal(protocol.FileWrittenData{
		RequestID:    requestID,
		BytesWritten: bytesWritten,
		Error:        errMsg,
	})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgFileWritten,
		ID:   requestID,
		Data: data,
	})
}

// HandleFileMkdir handles a mkdir request from the hub.
func (fm *Manager) HandleFileMkdir(transport MessageSender, msg protocol.Message) {
	var req protocol.FileMkdirData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid mkdir request: %v", err)
		return
	}

	root, relPath, _, err := fm.OpenRootPath(req.Path)
	if err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	defer root.Close()

	if err := root.MkdirAll(relPath, 0o750); err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}

	fm.SendFileResult(transport, req.RequestID, true, "")
}

// HandleFileDelete handles a file delete request from the hub.
func (fm *Manager) HandleFileDelete(transport MessageSender, msg protocol.Message) {
	var req protocol.FileDeleteData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid delete request: %v", err)
		return
	}

	root, relPath, filePath, err := fm.OpenRootPath(req.Path)
	if err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	defer root.Close()

	// Safety: don't allow deleting the base directory itself.
	if filepath.Clean(filePath) == filepath.Clean(fm.BaseDir) {
		fm.SendFileResult(transport, req.RequestID, false, "cannot delete base directory")
		return
	}
	if err := root.RemoveAll(relPath); err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}

	fm.SendFileResult(transport, req.RequestID, true, "")
}

// HandleFileRename handles a file rename request from the hub.
func (fm *Manager) HandleFileRename(transport MessageSender, msg protocol.Message) {
	var req protocol.FileRenameData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid rename request: %v", err)
		return
	}

	root, oldRel, oldPath, err := fm.OpenRootPath(req.OldPath)
	if err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	defer root.Close()

	newRoot, newRel, _, err := fm.OpenRootPath(req.NewPath)
	if err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	defer newRoot.Close()

	if filepath.Clean(oldPath) == filepath.Clean(fm.BaseDir) {
		fm.SendFileResult(transport, req.RequestID, false, "cannot rename base directory")
		return
	}

	// Ensure source exists.
	if _, err := root.Lstat(oldRel); err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	if _, err := newRoot.Lstat(newRel); err == nil {
		fm.SendFileResult(transport, req.RequestID, false, "destination already exists")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}

	if err := root.Rename(oldRel, newRel); err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}

	fm.SendFileResult(transport, req.RequestID, true, "")
}

// SendFileResult sends a generic file operation result to the hub.
func (fm *Manager) SendFileResult(transport MessageSender, requestID string, ok bool, errMsg string) {
	data, _ := json.Marshal(protocol.FileResultData{
		RequestID: requestID,
		OK:        ok,
		Error:     errMsg,
	})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgFileResult,
		ID:   requestID,
		Data: data,
	})
}

// SkipSearchDirs returns true for directories that should be skipped during file search.
var SkipSearchDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	".cache":       true,
}

// HandleFileSearch performs a recursive filename search under a base path,
// matching filenames against a glob pattern. Results are capped at MaxResults
// (default 100, max 500) and the walk is bounded to a 10-second context timeout.
func (fm *Manager) HandleFileSearch(transport MessageSender, msg protocol.Message) {
	var req protocol.FileSearchData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid search request: %v", err)
		return
	}

	sendResult := func(matches []protocol.FileEntry, truncated bool, errMsg string) {
		if matches == nil {
			matches = []protocol.FileEntry{}
		}
		data, _ := json.Marshal(protocol.FileSearchResultData{
			RequestID: req.RequestID,
			Matches:   matches,
			Error:     errMsg,
			Truncated: truncated,
		})
		_ = transport.Send(protocol.Message{
			Type: protocol.MsgFileSearchResult,
			ID:   req.RequestID,
			Data: data,
		})
	}

	root, searchRel, _, err := fm.OpenRootPath(req.Path)
	if err != nil {
		sendResult(nil, false, err.Error())
		return
	}
	defer root.Close()

	// Apply MaxResults bounds: default 100, cap at 500.
	maxResults := req.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}
	if maxResults > 500 {
		maxResults = 500
	}

	// Use empty pattern as a match-all wildcard.
	pattern := req.Pattern
	if strings.TrimSpace(pattern) == "" {
		pattern = "*"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var matches []protocol.FileEntry
	truncated := false

	searchRel = filepath.ToSlash(searchRel)
	walkErr := fs.WalkDir(root.FS(), searchRel, func(relPath string, d fs.DirEntry, err error) error {
		// Respect timeout.
		if ctx.Err() != nil {
			return fs.SkipAll
		}

		if err != nil {
			return nil // skip inaccessible paths
		}

		// Skip excluded directories in-place.
		if d.IsDir() && SkipSearchDirs[d.Name()] {
			return fs.SkipDir
		}

		// Only match filenames (not the root search path itself).
		if relPath == searchRel {
			return nil
		}

		matched, matchErr := filepath.Match(pattern, d.Name())
		if matchErr != nil {
			// Invalid pattern -- abort walk and surface the error.
			return matchErr
		}
		if !matched {
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}

		displayPath := filepath.Join(fm.BaseDir, filepath.FromSlash(relPath))
		matches = append(matches, protocol.FileEntry{
			Name:    d.Name(),
			Path:    displayPath,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
			IsDir:   d.IsDir(),
		})

		if len(matches) >= maxResults {
			truncated = true
			return fs.SkipAll
		}

		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		sendResult(matches, truncated, walkErr.Error())
		return
	}

	// Timeout hit: mark as truncated.
	if ctx.Err() != nil {
		truncated = true
	}

	sendResult(matches, truncated, "")
}
