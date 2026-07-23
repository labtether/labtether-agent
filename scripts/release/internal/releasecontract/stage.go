package releasecontract

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ValidateStage(stage string) (string, error) {
	if stage == "" || !filepath.IsAbs(stage) {
		return "", errors.New("release stage must be an absolute path")
	}
	info, err := os.Lstat(stage)
	if err != nil {
		return "", fmt.Errorf("inspect release stage: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("release stage must be a non-symlink directory")
	}
	resolved, err := filepath.EvalSymlinks(stage)
	if err != nil {
		return "", fmt.Errorf("resolve release stage: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve absolute release stage: %w", err)
	}
	if filepath.Clean(stage) != resolved {
		return "", errors.New("release stage path must not traverse symlinked ancestors")
	}
	if err := validateStagePermissions(info); err != nil {
		return "", err
	}
	return resolved, nil
}

func ValidateExternalStage(stage, repositoryRoot string) (string, error) {
	resolvedStage, err := ValidateStage(stage)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	resolvedRoot, err = filepath.Abs(resolvedRoot)
	if err != nil {
		return "", fmt.Errorf("resolve absolute repository root: %w", err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedStage)
	if err != nil {
		return "", fmt.Errorf("compare release stage and repository: %w", err)
	}
	if relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return "", errors.New("release stage must be outside the repository")
	}
	return resolvedStage, nil
}

func EnsureRegularFile(path string, maxBytes int64) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file must be a regular non-symlink file")
	}
	if info.Size() <= 0 {
		return nil, errors.New("file must not be empty")
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return info, nil
}

func HashRegularFile(path string, maxBytes int64) (AssetDigest, error) {
	var result AssetDigest
	before, err := EnsureRegularFile(path, maxBytes)
	if err != nil {
		return result, err
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return result, errors.New("file changed while it was opened")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return result, err
	}
	if written > maxBytes {
		return result, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() ||
		!after.ModTime().Equal(opened.ModTime()) || written != opened.Size() {
		return result, errors.New("file changed while it was hashed")
	}
	result.Name = filepath.Base(path)
	result.SHA256 = fmt.Sprintf("%x", hasher.Sum(nil))
	result.SizeBytes = written
	return result, nil
}

func WriteNoReplace(path string, data []byte, mode os.FileMode) error {
	if !ValidSafeBaseName(filepath.Base(path)) {
		return errors.New("unsafe output filename")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return errors.New("output parent must be a non-symlink directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create no-replace output: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
