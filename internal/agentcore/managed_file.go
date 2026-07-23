package agentcore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	maxLocalSecretFileBytes = 64 * 1024
	maxLocalCAFileBytes     = 1024 * 1024
	maxDeviceKeyFileBytes   = 4 * 1024
	maxAppliedConfigBytes   = 64 * 1024
)

// readBoundedRegularFile opens one stable regular-file object, rejecting final
// symlinks and size changes between path inspection and open. Reading through
// the descriptor avoids a second path traversal after validation.
func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid file size limit")
	}
	before, err := os.Lstat(path) // #nosec G703 -- callers provide intentional local runtime/config paths; this helper then rejects non-regular targets.
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular file %s", path)
	}

	file, err := os.Open(path) // #nosec G304,G703 -- caller supplies an intentional local runtime/config path; descriptor identity is verified below.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("file changed while opening %s", path)
	}
	if opened.Size() < 0 || opened.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}

// writeManagedFileAtomic writes a new inode beside the destination and then
// atomically replaces the destination. A pre-created symlink at the final path
// is replaced as a directory entry rather than followed.
func writeManagedFileAtomic(path string, data []byte, mode os.FileMode, secret bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing unsafe managed directory %s", dir)
	}

	tmp, err := os.CreateTemp(dir, ".labtether-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if secret {
		if err := hardenSecretFile(tmpPath); err != nil {
			return fmt.Errorf("secure managed file ACL: %w", err)
		}
	}
	if err := replaceManagedFile(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}
