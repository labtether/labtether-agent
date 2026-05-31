package files

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/labtether/protocol"
)

// CleanupOrphanedTempFiles removes .lt-upload-* temp files older than 5 minutes
// that were left behind by interrupted uploads.
func (fm *Manager) CleanupOrphanedTempFiles() {
	if strings.TrimSpace(fm.BaseDir) == "" {
		return
	}

	cutoff := time.Now().Add(-5 * time.Minute)
	startedAt := time.Now()
	visited := 0
	budgetExceeded := false
	root, err := os.OpenRoot(fm.BaseDir)
	if err != nil {
		log.Printf("file: orphan temp cleanup skipped for %s: %v", fm.BaseDir, err)
		return
	}
	defer root.Close()

	_ = fs.WalkDir(root.FS(), ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible dirs
		}
		visited++
		if visited > orphanCleanupMaxEntries || time.Since(startedAt) > orphanCleanupScanBudget {
			budgetExceeded = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasPrefix(d.Name(), ".lt-upload-") {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			displayPath := filepath.Join(fm.BaseDir, filepath.FromSlash(relPath))
			if rmErr := root.Remove(relPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				log.Printf("file: failed to clean orphaned temp file %s: %v", displayPath, rmErr)
			} else {
				log.Printf("file: cleaned up orphaned temp file: %s", displayPath)
			}
		}
		return nil
	})
	if budgetExceeded {
		log.Printf(
			"file: orphan temp cleanup scan truncated (base=%s visited=%d budget=%s)",
			fm.BaseDir,
			visited,
			orphanCleanupScanBudget,
		)
	}
}

// HandleFileWrite handles a file write (upload) request from the hub.
func (fm *Manager) HandleFileWrite(transport MessageSender, msg protocol.Message) {
	var req protocol.FileWriteData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid write request: %v", err)
		return
	}

	bytesWritten, err := fm.WriteChunk(req)
	if err != nil {
		fm.SendFileWritten(transport, req.RequestID, bytesWritten, err.Error())
		return
	}
	if req.Done {
		fm.SendFileWritten(transport, req.RequestID, bytesWritten, "")
	}
}

// WriteChunk processes a single upload chunk, returning bytes written so far.
func (fm *Manager) WriteChunk(req protocol.FileWriteData) (int64, error) {
	req.RequestID = strings.TrimSpace(req.RequestID)
	if req.RequestID == "" {
		return 0, errors.New("request_id is required")
	}
	filePath, err := fm.ValidatePathNoFollowFinal(req.Path)
	if err != nil {
		return 0, err
	}

	fm.mu.Lock()
	if fm.writers == nil {
		fm.writers = make(map[string]*PendingWrite)
	}
	pw, exists := fm.writers[req.RequestID]
	if !exists {
		if len(fm.writers) >= maxWritePending {
			fm.mu.Unlock()
			return 0, errors.New("too many concurrent uploads (64 max); wait for current uploads to finish")
		}
		// Create temp file in the target directory.
		dir := filepath.Dir(filePath)
		if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
			fm.mu.Unlock()
			return 0, mkErr
		}
		recheckedPath, checkErr := fm.ValidatePathNoFollowFinal(req.Path)
		if checkErr != nil {
			fm.mu.Unlock()
			return 0, checkErr
		}
		if recheckedPath != filePath {
			fm.mu.Unlock()
			return 0, errors.New("upload path changed during validation")
		}
		tmpFile, tmpErr := os.CreateTemp(dir, ".lt-upload-*")
		if tmpErr != nil {
			fm.mu.Unlock()
			return 0, tmpErr
		}
		pw = &PendingWrite{
			File:    tmpFile,
			Path:    filePath,
			TmpPath: tmpFile.Name(),
		}
		fm.writers[req.RequestID] = pw
	} else if pw.Path != filePath {
		fm.mu.Unlock()
		fm.cleanupPendingWrite(req.RequestID, pw)
		return 0, errors.New("upload request_id path mismatch")
	}
	fm.mu.Unlock()

	// Decode and write chunk.
	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		fm.cleanupPendingWrite(req.RequestID, pw)
		return 0, errors.New("invalid base64 data")
	}

	pw.mu.Lock()
	if pw.Closed {
		pw.mu.Unlock()
		return pw.Written, errors.New("upload is already closed")
	}

	if req.Offset != pw.Written {
		written := pw.Written
		fm.cleanupWriteLocked(req.RequestID, pw)
		pw.mu.Unlock()
		return written, errors.New("upload chunk offset mismatch")
	}

	// Enforce cumulative size limit to prevent disk exhaustion.
	if pw.Written+int64(len(decoded)) > MaxFileSize {
		written := pw.Written
		fm.cleanupWriteLocked(req.RequestID, pw)
		pw.mu.Unlock()
		return written, errors.New("file exceeds 512 MB limit")
	}

	n, err := pw.File.Write(decoded)
	if err != nil {
		written := pw.Written
		fm.cleanupWriteLocked(req.RequestID, pw)
		pw.mu.Unlock()
		return written, err
	}
	pw.Written += int64(n)

	if req.Done {
		if closeErr := pw.File.Close(); closeErr != nil {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, closeErr
		}
		// Atomic rename from temp to final path.
		recheckedPath, checkErr := fm.ValidatePathNoFollowFinal(req.Path)
		if checkErr != nil {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, checkErr
		}
		if recheckedPath != pw.Path {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, errors.New("upload path changed during validation")
		}
		if err := os.Rename(pw.TmpPath, pw.Path); err != nil {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, err
		}
		pw.Closed = true
		fm.removePendingWrite(req.RequestID, pw)
	}
	written := pw.Written
	pw.mu.Unlock()
	return written, nil
}

func (fm *Manager) cleanupPendingWrite(requestID string, pw *PendingWrite) {
	if pw == nil {
		return
	}
	pw.mu.Lock()
	defer pw.mu.Unlock()
	fm.cleanupWriteLocked(requestID, pw)
}

func (fm *Manager) removePendingWrite(requestID string, pw *PendingWrite) {
	fm.mu.Lock()
	if fm.writers != nil && fm.writers[requestID] == pw {
		delete(fm.writers, requestID)
	}
	fm.mu.Unlock()
}

func (fm *Manager) cleanupWriteLocked(requestID string, pw *PendingWrite) {
	if pw == nil || pw.Closed {
		fm.removePendingWrite(requestID, pw)
		return
	}
	pw.Closed = true
	fm.removePendingWrite(requestID, pw)
	if closeErr := pw.File.Close(); closeErr != nil {
		log.Printf("file: failed to close pending writer %s: %v", requestID, closeErr)
	}
	if rmErr := os.Remove(pw.TmpPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		log.Printf("file: failed to remove temp upload %s: %v", pw.TmpPath, rmErr)
	}
}

// HasPendingWrite returns true if there is a pending write for the given request ID.
// This is primarily used for testing cleanup behavior.
func (fm *Manager) HasPendingWrite(requestID string) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if fm.writers == nil {
		return false
	}
	_, ok := fm.writers[requestID]
	return ok
}

// CloseAll shuts down all pending file writers and removes temp files.
func (fm *Manager) CloseAll() {
	fm.mu.Lock()
	pending := make(map[string]*PendingWrite, len(fm.writers))
	for id, pw := range fm.writers {
		pending[id] = pw
		delete(fm.writers, id)
	}
	fm.mu.Unlock()
	for id, pw := range pending {
		pw.mu.Lock()
		fm.cleanupWriteLocked(id, pw)
		pw.mu.Unlock()
	}
}
