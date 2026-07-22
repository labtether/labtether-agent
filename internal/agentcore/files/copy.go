package files

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/labtether/protocol"
)

const (
	maxCopyEntries  = 20_000
	maxCopyBytes    = int64(MaxFileSize)
	maxCopyFileSize = int64(MaxFileSize)
	maxCopyDepth    = 64
	maxCopyDuration = 5 * time.Minute
	copyReadBatch   = 256
	copyBufferSize  = 64 * 1024
)

var errCopyLimitExceeded = errors.New("copy exceeds safe limits")

type copyLimits struct {
	maxEntries  int
	maxBytes    int64
	maxFileSize int64
	maxDepth    int
	maxDuration time.Duration
	readBatch   int
	bufferSize  int
}

var defaultCopyLimits = copyLimits{
	maxEntries:  maxCopyEntries,
	maxBytes:    maxCopyBytes,
	maxFileSize: maxCopyFileSize,
	maxDepth:    maxCopyDepth,
	maxDuration: maxCopyDuration,
	readBatch:   copyReadBatch,
	bufferSize:  copyBufferSize,
}

type copyBackend interface {
	Lstat(path string) (os.FileInfo, error)
	MkdirAll(path string, mode os.FileMode) error
	Mkdir(path string, mode os.FileMode) error
	Open(path string) (*os.File, error)
	OpenFile(path string, flag int, mode os.FileMode) (*os.File, error)
	RemoveAll(path string) error
}

type rootedCopyBackend struct {
	root *os.Root
}

func (b rootedCopyBackend) Lstat(path string) (os.FileInfo, error) {
	return b.root.Lstat(path)
}

func (b rootedCopyBackend) MkdirAll(path string, mode os.FileMode) error {
	return b.root.MkdirAll(path, mode)
}

func (b rootedCopyBackend) Mkdir(path string, mode os.FileMode) error {
	return b.root.Mkdir(path, mode)
}

func (b rootedCopyBackend) Open(path string) (*os.File, error) {
	return b.root.Open(path)
}

func (b rootedCopyBackend) OpenFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	return b.root.OpenFile(path, flag, mode)
}

func (b rootedCopyBackend) RemoveAll(path string) error {
	return b.root.RemoveAll(path)
}

type localCopyBackend struct{}

func (localCopyBackend) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func (localCopyBackend) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (localCopyBackend) Mkdir(path string, mode os.FileMode) error {
	return os.Mkdir(path, mode)
}

func (localCopyBackend) Open(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- Paths are validated by the file manager or explicit helper caller.
}

func (localCopyBackend) OpenFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, mode) // #nosec G304 -- Paths are validated by the file manager or explicit helper caller.
}

func (localCopyBackend) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

type copyState struct {
	ctx                context.Context
	limits             copyLimits
	entries            int
	bytes              int64
	destinationCreated bool
}

// HandleFileCopy handles a file copy request from the hub.
func (fm *Manager) HandleFileCopy(transport MessageSender, msg protocol.Message) {
	fm.HandleFileCopyContext(context.Background(), transport, msg)
}

// HandleFileCopyContext handles a bounded copy and stops when the receive-loop
// lifecycle ends. The background-context wrapper remains for direct callers.
func (fm *Manager) HandleFileCopyContext(ctx context.Context, transport MessageSender, msg protocol.Message) {
	if ctx == nil {
		ctx = context.Background()
	}
	var req protocol.FileCopyData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid copy request: %v", err)
		return
	}

	root, srcRel, srcPath, err := fm.OpenRootPath(req.SrcPath)
	if err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	defer root.Close()

	dstRoot, dstRel, dstPath, err := fm.OpenRootPath(req.DstPath)
	if err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	defer dstRoot.Close()

	if srcPath == dstPath {
		fm.SendFileResult(transport, req.RequestID, false, "source and destination are identical")
		return
	}
	if _, err := root.Lstat(srcRel); err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	if _, err := dstRoot.Lstat(dstRel); err == nil {
		fm.SendFileResult(transport, req.RequestID, false, "destination already exists")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}

	if err := copyPathRecursiveRootContext(ctx, root, srcRel, dstRel, defaultCopyLimits); err != nil {
		fm.SendFileResult(transport, req.RequestID, false, err.Error())
		return
	}
	fm.SendFileResult(transport, req.RequestID, true, "")
}

func copyPathRecursiveRoot(root *os.Root, srcRel, dstRel string) error {
	return copyPathRecursiveRootContext(context.Background(), root, srcRel, dstRel, defaultCopyLimits)
}

func copyPathRecursiveRootContext(ctx context.Context, root *os.Root, srcRel, dstRel string, limits copyLimits) error {
	if root == nil {
		return errors.New("copy root is required")
	}
	srcRel = filepath.Clean(srcRel)
	dstRel = filepath.Clean(dstRel)
	if srcRel == dstRel {
		return errors.New("source and destination are identical")
	}
	if PathWithinBaseDir(srcRel, dstRel) {
		return errors.New("destination cannot be inside source directory")
	}
	return copyPathWithBackend(ctx, rootedCopyBackend{root: root}, srcRel, dstRel, limits)
}

// CopyPathRecursive copies a file or directory tree from srcPath to dstPath.
// Symlinks are rejected for safety and the destination must not exist.
func CopyPathRecursive(srcPath, dstPath string) error {
	return CopyPathRecursiveContext(context.Background(), srcPath, dstPath)
}

// CopyPathRecursiveContext is the cancellable form of CopyPathRecursive.
func CopyPathRecursiveContext(ctx context.Context, srcPath, dstPath string) error {
	return copyPathRecursiveWithLimits(ctx, srcPath, dstPath, defaultCopyLimits)
}

func copyPathRecursiveWithLimits(ctx context.Context, srcPath, dstPath string, limits copyLimits) error {
	srcInfo, err := os.Lstat(srcPath)
	if err != nil {
		return err
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("copying symlinks is not supported")
	}
	if _, err := os.Lstat(dstPath); err == nil {
		return errors.New("destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dstContainmentPath, err := copyDestinationContainmentPath(dstPath)
	if err != nil {
		return err
	}
	srcContainmentPath, err := filepath.EvalSymlinks(srcPath)
	if err != nil {
		return err
	}
	if srcContainmentPath == dstContainmentPath {
		return errors.New("source and destination are identical")
	}
	if srcInfo.IsDir() && PathWithinBaseDir(srcContainmentPath, dstContainmentPath) {
		return errors.New("destination cannot be inside source directory")
	}
	return copyPathWithBackend(ctx, localCopyBackend{}, srcPath, dstPath, limits)
}

func copyPathWithBackend(ctx context.Context, backend copyBackend, srcPath, dstPath string, limits copyLimits) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateCopyLimits(limits); err != nil {
		return err
	}
	copyCtx := ctx
	cancel := func() {}
	if limits.maxDuration > 0 {
		copyCtx, cancel = context.WithTimeout(ctx, limits.maxDuration)
	}
	defer cancel()

	state := &copyState{ctx: copyCtx, limits: limits}
	copyErr := state.copyPath(backend, srcPath, dstPath, 0)
	if copyErr == nil || !state.destinationCreated {
		return copyErr
	}
	if cleanupErr := backend.RemoveAll(dstPath); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
		return errors.Join(copyErr, fmt.Errorf("remove partial copy destination: %w", cleanupErr))
	}
	return copyErr
}

func validateCopyLimits(limits copyLimits) error {
	switch {
	case limits.maxEntries <= 0:
		return errors.New("copy entry limit must be positive")
	case limits.maxBytes <= 0:
		return errors.New("copy byte limit must be positive")
	case limits.maxFileSize <= 0:
		return errors.New("copy file-size limit must be positive")
	case limits.maxDepth < 0:
		return errors.New("copy depth limit cannot be negative")
	case limits.readBatch <= 0:
		return errors.New("copy directory batch size must be positive")
	case limits.bufferSize <= 0:
		return errors.New("copy buffer size must be positive")
	default:
		return nil
	}
}

func (state *copyState) copyPath(backend copyBackend, srcPath, dstPath string, depth int) error {
	if err := state.checkContext(); err != nil {
		return err
	}
	if depth > state.limits.maxDepth {
		return fmt.Errorf("%w: directory depth exceeds %d", errCopyLimitExceeded, state.limits.maxDepth)
	}
	state.entries++
	if state.entries > state.limits.maxEntries {
		return fmt.Errorf("%w: more than %d entries", errCopyLimitExceeded, state.limits.maxEntries)
	}

	srcInfo, err := backend.Lstat(srcPath)
	if err != nil {
		return err
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("copying symlinks is not supported")
	}
	if depth == 0 {
		if err := backend.MkdirAll(filepath.Dir(dstPath), 0o750); err != nil {
			return err
		}
	}

	if srcInfo.IsDir() {
		if err := backend.Mkdir(dstPath, srcInfo.Mode().Perm()); err != nil {
			return err
		}
		if depth == 0 {
			state.destinationCreated = true
		}
		dir, err := backend.Open(srcPath)
		if err != nil {
			return err
		}
		defer dir.Close()

		for {
			if err := state.checkContext(); err != nil {
				return err
			}
			entries, readErr := dir.ReadDir(state.limits.readBatch)
			for _, entry := range entries {
				if err := state.copyPath(
					backend,
					filepath.Join(srcPath, entry.Name()),
					filepath.Join(dstPath, entry.Name()),
					depth+1,
				); err != nil {
					return err
				}
			}
			switch {
			case errors.Is(readErr, io.EOF):
				return nil
			case readErr != nil:
				return readErr
			case len(entries) == 0:
				return io.ErrNoProgress
			}
		}
	}

	if !srcInfo.Mode().IsRegular() {
		return errors.New("copying special files is not supported")
	}
	if srcInfo.Size() < 0 {
		return errors.New("copy source reported a negative file size")
	}
	if srcInfo.Size() > state.limits.maxFileSize {
		return fmt.Errorf("%w: file exceeds %d bytes", errCopyLimitExceeded, state.limits.maxFileSize)
	}
	if srcInfo.Size() > state.limits.maxBytes-state.bytes {
		return fmt.Errorf("%w: total data exceeds %d bytes", errCopyLimitExceeded, state.limits.maxBytes)
	}

	src, err := backend.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := backend.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, srcInfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer dst.Close()
	if depth == 0 {
		state.destinationCreated = true
	}

	if err := state.copyRegularFile(dst, src); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	return state.checkContext()
}

func (state *copyState) copyRegularFile(dst io.Writer, src io.Reader) error {
	buffer := make([]byte, state.limits.bufferSize)
	var fileBytes int64
	for {
		if err := state.checkContext(); err != nil {
			return err
		}
		fileRemaining := state.limits.maxFileSize - fileBytes
		totalRemaining := state.limits.maxBytes - state.bytes
		readSize := int64(len(buffer))
		if fileRemaining < readSize {
			readSize = fileRemaining + 1
		}
		if totalRemaining < readSize {
			readSize = totalRemaining + 1
		}
		if readSize < 1 {
			readSize = 1
		}

		n, readErr := src.Read(buffer[:int(readSize)])
		if n < 0 || n > int(readSize) {
			return fmt.Errorf("invalid copy read count %d", n)
		}
		if err := state.checkContext(); err != nil {
			return err
		}
		if n > 0 {
			if int64(n) > fileRemaining {
				return fmt.Errorf("%w: file exceeds %d bytes", errCopyLimitExceeded, state.limits.maxFileSize)
			}
			if int64(n) > totalRemaining {
				return fmt.Errorf("%w: total data exceeds %d bytes", errCopyLimitExceeded, state.limits.maxBytes)
			}
			written, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			fileBytes += int64(written)
			state.bytes += int64(written)
		}
		if err := state.checkContext(); err != nil {
			return err
		}
		switch {
		case errors.Is(readErr, io.EOF):
			return nil
		case readErr != nil:
			return readErr
		case n == 0:
			return io.ErrNoProgress
		}
	}
}

func (state *copyState) checkContext() error {
	if err := state.ctx.Err(); err != nil {
		return fmt.Errorf("copy canceled: %w", err)
	}
	return nil
}

func copyDestinationContainmentPath(dstPath string) (string, error) {
	cleaned := filepath.Clean(dstPath)
	resolvedParent, err := resolveExistingPathForContainment(filepath.Dir(cleaned))
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(cleaned)), nil
}
