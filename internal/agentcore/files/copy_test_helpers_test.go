package files

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// localCopyBackend exists only to exercise the generic copy engine against
// temporary test directories. Production copies always use rootedCopyBackend.
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
	return os.Open(path)
}

func (localCopyBackend) OpenFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, mode)
}

func (localCopyBackend) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func CopyPathRecursive(srcPath, dstPath string) error {
	return CopyPathRecursiveContext(context.Background(), srcPath, dstPath)
}

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

func copyDestinationContainmentPath(dstPath string) (string, error) {
	cleaned := filepath.Clean(dstPath)
	resolvedParent, err := resolveExistingPathForContainment(filepath.Dir(cleaned))
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(cleaned)), nil
}
