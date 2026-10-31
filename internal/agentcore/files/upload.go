package files

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	for _, root := range fm.scope().roots {
		fm.cleanupOrphanedTempFiles(root)
	}
}

func (fm *Manager) cleanupOrphanedTempFiles(baseDir string) {
	if strings.TrimSpace(baseDir) == "" {
		return
	}

	cutoff := time.Now().Add(-5 * time.Minute)
	startedAt := time.Now()
	visited := 0
	budgetExceeded := false
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		log.Printf("file: orphan temp cleanup skipped for %s: %v", baseDir, err)
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
			displayPath := filepath.Join(baseDir, filepath.FromSlash(relPath))
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
			baseDir,
			visited,
			orphanCleanupScanBudget,
		)
	}
}

// HandleFileWrite handles a file write (upload) request from the hub.
func (fm *Manager) HandleFileWrite(transport MessageSender, msg protocol.Message) {
	fm.HandleFileWriteContext(context.Background(), transport, msg)
}

// HandleFileWriteContext binds a queued chunk to the socket that received it.
func (fm *Manager) HandleFileWriteContext(ctx context.Context, transport MessageSender, msg protocol.Message) {
	var req protocol.FileWriteData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid write request: %v", err)
		return
	}

	bytesWritten, err := fm.WriteChunkContext(ctx, req)
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
	return fm.WriteChunkContext(context.Background(), req)
}

// WriteChunkContext checks ownership before allocation and at final rename.
// CloseAll invalidates work that was already queued or preparing a path.
func (fm *Manager) WriteChunkContext(ctx context.Context, req protocol.FileWriteData) (int64, error) {
	fm.mu.Lock()
	epoch, ctxErr := fm.writeEpoch, ctx.Err()
	fm.mu.Unlock()
	if ctxErr != nil {
		return 0, ctxErr
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	if req.RequestID == "" {
		return 0, errors.New("request_id is required")
	}
	if len(req.RequestID) > maxFileWriteRequestIDLen {
		return 0, fmt.Errorf("request_id exceeds %d byte limit", maxFileWriteRequestIDLen)
	}
	if req.Offset < 0 {
		written := fm.abortPendingWriteContext(ctx, epoch, req.RequestID)
		return written, errors.New("upload chunk offset cannot be negative")
	}
	maxEncodedChunkSize := base64.StdEncoding.EncodedLen(FileChunkSize)
	if len(req.Data) > maxEncodedChunkSize {
		written := fm.abortPendingWriteContext(ctx, epoch, req.RequestID)
		return written, fmt.Errorf("upload chunk exceeds %d byte limit", FileChunkSize)
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		written := fm.abortPendingWriteContext(ctx, epoch, req.RequestID)
		return written, errors.New("invalid base64 data")
	}
	if len(decoded) > FileChunkSize {
		written := fm.abortPendingWriteContext(ctx, epoch, req.RequestID)
		return written, fmt.Errorf("upload chunk exceeds %d byte limit", FileChunkSize)
	}
	if len(decoded) == 0 && !req.Done {
		written := fm.abortPendingWriteContext(ctx, epoch, req.RequestID)
		return written, errors.New("empty upload chunk must be final")
	}

	// Reap stale uploads before enforcing the per-agent/session slot bound so
	// abandoned requests cannot deny all future uploads until reconnect.
	fm.cleanupExpiredPendingWrites(fm.pendingWriteTime())

	target, err := fm.openScopedPath(req.Path)
	if err != nil {
		written := fm.abortPendingWriteContext(ctx, epoch, req.RequestID)
		return written, err
	}

	requestRoot, relPath, filePath := target.root, target.rel, target.display

	fm.mu.Lock()
	if err := fm.uploadOwnerErrorLocked(ctx, epoch); err != nil {
		fm.mu.Unlock()
		_ = requestRoot.Close()
		return 0, err
	}
	if fm.writers == nil {
		fm.writers = make(map[string]*PendingWrite)
	}
	pw, exists := fm.writers[req.RequestID]
	if !exists {
		if len(fm.writers) >= maxWritePending {
			fm.mu.Unlock()
			_ = requestRoot.Close()
			return 0, errors.New("too many concurrent uploads (64 max); wait for current uploads to finish")
		}
		// Create the parent and temporary file through os.Root so a concurrent
		// symlink swap cannot redirect the upload outside BaseDir.
		dirRel := filepath.Dir(relPath)
		if mkErr := mkdirIfMissing(requestRoot, dirRel, 0o750); mkErr != nil {
			fm.mu.Unlock()
			_ = requestRoot.Close()
			return 0, mkErr
		}
		tmpFile, tmpRelPath, tmpErr := createTempInRoot(requestRoot, dirRel)
		if tmpErr != nil {
			fm.mu.Unlock()
			_ = requestRoot.Close()
			return 0, tmpErr
		}
		pw = &PendingWrite{
			File:         tmpFile,
			Root:         requestRoot,
			Path:         filePath,
			RelPath:      relPath,
			TmpPath:      filepath.Join(target.base, tmpRelPath),
			TmpRelPath:   tmpRelPath,
			lastActivity: fm.pendingWriteTime(),
		}
		fm.writers[req.RequestID] = pw
		fm.armPendingWriteExpiryLocked(req.RequestID, pw, fm.writeIdleTTL())
	} else if pw.Path != filePath {
		fm.mu.Unlock()
		_ = requestRoot.Close()
		fm.cleanupPendingWrite(req.RequestID, pw)
		return 0, errors.New("upload request_id path mismatch")
	} else {
		_ = requestRoot.Close()
	}
	fm.mu.Unlock()

	pw.mu.Lock()
	fm.mu.Lock()
	ownerErr := fm.uploadOwnerErrorLocked(ctx, epoch)
	fm.mu.Unlock()
	if ownerErr != nil {
		written := pw.Written
		fm.cleanupWriteLocked(req.RequestID, pw)
		pw.mu.Unlock()
		return written, ownerErr
	}
	if pw.Closed {
		written := pw.Written
		pw.mu.Unlock()
		return written, errors.New("upload is already closed")
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
	pw.lastActivity = fm.pendingWriteTime()

	if req.Done {
		if syncErr := pw.File.Sync(); syncErr != nil {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, syncErr
		}
		if closeErr := pw.File.Close(); closeErr != nil {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, closeErr
		}
		// The ownership check and atomic rename share CloseAll's manager lock.
		// A socket cancellation or reconnect during the write/fsync cannot commit
		// its old temporary file into the destination afterward.
		fm.mu.Lock()
		commitErr := fm.uploadOwnerErrorLocked(ctx, epoch)
		if commitErr == nil {
			commitErr = pw.Root.Rename(pw.TmpRelPath, pw.RelPath)
		}
		fm.mu.Unlock()
		if err := commitErr; err != nil {
			written := pw.Written
			fm.cleanupWriteLocked(req.RequestID, pw)
			pw.mu.Unlock()
			return written, err
		}
		fm.stopPendingWriteTimerLocked(pw)
		pw.Closed = true
		_ = pw.Root.Close()
		pw.Root = nil
		fm.removePendingWrite(req.RequestID, pw)
	}
	written := pw.Written
	pw.mu.Unlock()
	return written, nil
}

func createTempInRoot(root *os.Root, dirRel string) (*os.File, string, error) {
	for range 100 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".lt-upload-" + hex.EncodeToString(random[:])
		rel := filepath.Join(dirRel, name)
		file, err := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return file, rel, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate a unique upload temporary file")
}

func (fm *Manager) cleanupPendingWrite(requestID string, pw *PendingWrite) {
	if pw == nil {
		return
	}
	pw.mu.Lock()
	defer pw.mu.Unlock()
	fm.cleanupWriteLocked(requestID, pw)
}

// uploadOwnerErrorLocked requires fm.mu.
func (fm *Manager) uploadOwnerErrorLocked(ctx context.Context, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if fm.writeEpoch != epoch {
		return context.Canceled
	}
	return nil
}

func (fm *Manager) abortPendingWriteContext(ctx context.Context, epoch uint64, requestID string) int64 {
	fm.mu.Lock()
	if fm.uploadOwnerErrorLocked(ctx, epoch) != nil {
		fm.mu.Unlock()
		return 0
	}
	pw := fm.writers[requestID]
	fm.mu.Unlock()
	if pw == nil {
		return 0
	}

	pw.mu.Lock()
	fm.mu.Lock()
	ownerErr := fm.uploadOwnerErrorLocked(ctx, epoch)
	fm.mu.Unlock()
	written := pw.Written
	if ownerErr == nil {
		fm.cleanupWriteLocked(requestID, pw)
	}
	pw.mu.Unlock()
	return written
}

// AbortWrite drops an unfinished upload and removes its temporary file. The
// ordered upload writer calls it after the socket reader gave up on the
// request because the writer fell too far behind.
func (fm *Manager) AbortWrite(requestID string) {
	fm.mu.Lock()
	epoch := fm.writeEpoch
	fm.mu.Unlock()
	fm.abortPendingWriteContext(context.Background(), epoch, strings.TrimSpace(requestID))
}

func (fm *Manager) pendingWriteTime() time.Time {
	if fm.pendingWriteNow != nil {
		return fm.pendingWriteNow()
	}
	return time.Now()
}

func (fm *Manager) writeIdleTTL() time.Duration {
	if fm.pendingWriteIdleTTL > 0 {
		return fm.pendingWriteIdleTTL
	}
	return pendingWriteIdleTTL
}

func (fm *Manager) armPendingWriteExpiryLocked(requestID string, pw *PendingWrite, after time.Duration) {
	if pw == nil || pw.Closed {
		return
	}
	if after <= 0 {
		after = time.Millisecond
	}
	if pw.idleTimer != nil {
		pw.idleTimer.Stop()
	}
	pw.idleTimer = time.AfterFunc(after, func() {
		fm.expirePendingWrite(requestID, pw, fm.pendingWriteTime())
	})
}

func (fm *Manager) expirePendingWrite(requestID string, pw *PendingWrite, now time.Time) bool {
	if pw == nil {
		return false
	}
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.Closed {
		return false
	}

	ttl := fm.writeIdleTTL()
	idleFor := now.Sub(pw.lastActivity)
	if idleFor < 0 {
		idleFor = 0
	}
	if idleFor < ttl {
		fm.armPendingWriteExpiryLocked(requestID, pw, ttl-idleFor)
		return false
	}

	written := pw.Written
	fm.cleanupWriteLocked(requestID, pw)
	log.Printf("file: expired idle upload request_id=%s bytes_written=%d idle=%s", requestID, written, idleFor)
	return true
}

func (fm *Manager) cleanupExpiredPendingWrites(now time.Time) int {
	fm.mu.Lock()
	pending := make(map[string]*PendingWrite, len(fm.writers))
	for requestID, pw := range fm.writers {
		pending[requestID] = pw
	}
	fm.mu.Unlock()

	expired := 0
	for requestID, pw := range pending {
		if fm.expirePendingWrite(requestID, pw, now) {
			expired++
		}
	}
	return expired
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
	fm.stopPendingWriteTimerLocked(pw)
	if closeErr := pw.File.Close(); closeErr != nil {
		log.Printf("file: failed to close pending writer %s: %v", requestID, closeErr)
	}
	if pw.Root == nil {
		log.Printf("file: pending upload %s is missing its file root", requestID)
	} else {
		if rmErr := pw.Root.Remove(pw.TmpRelPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			log.Printf("file: failed to remove temp upload for %s: %v", requestID, rmErr)
		}
		_ = pw.Root.Close()
		pw.Root = nil
	}
	// Keep the request visible as pending until its file handle and temporary
	// path have both been cleaned. Callers use absence from this map as the
	// completion boundary; deleting the entry first allowed them to observe a
	// supposedly expired upload while its .lt-upload-* file still existed.
	fm.removePendingWrite(requestID, pw)
}

func (fm *Manager) stopPendingWriteTimerLocked(pw *PendingWrite) {
	if pw != nil && pw.idleTimer != nil {
		pw.idleTimer.Stop()
		pw.idleTimer = nil
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
	fm.writeEpoch++
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
