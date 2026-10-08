package releasecontract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

// HashReleaseBinary hashes a bounded, stable, regular artifact without following symlinks.
func HashReleaseBinary(path string, maxBytes int64) (string, int64, error) {
	if maxBytes <= 0 {
		return "", 0, errors.New("release binary size limit must be positive")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("inspect release binary: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return "", 0, errors.New("release binary must be a regular non-symlink file")
	}
	if pathInfo.Size() <= 0 {
		return "", 0, errors.New("release binary must not be empty")
	}
	if pathInfo.Size() > maxBytes {
		return "", 0, fmt.Errorf("release binary exceeds %d bytes", maxBytes)
	}

	// #nosec G304 -- the caller-selected release artifact is validated with
	// Lstat, SameFile, regular-file, size, and before/after stability checks.
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open release binary: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat opened release binary: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return "", 0, errors.New("release binary changed while it was opened")
	}

	hasher := sha256.New()
	size, err := copyBoundedHash(hasher, file, maxBytes)
	if err != nil {
		return "", 0, err
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("restat release binary: %w", err)
	}
	if size != openedInfo.Size() || afterInfo.Size() != openedInfo.Size() || !afterInfo.ModTime().Equal(openedInfo.ModTime()) {
		return "", 0, errors.New("release binary changed while it was hashed")
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func copyBoundedHash(destination hash.Hash, source io.Reader, maxBytes int64) (int64, error) {
	written, err := io.Copy(destination, io.LimitReader(source, maxBytes+1))
	if err != nil {
		return 0, fmt.Errorf("hash release binary: %w", err)
	}
	if written > maxBytes {
		return 0, fmt.Errorf("release binary exceeds %d bytes", maxBytes)
	}
	return written, nil
}
