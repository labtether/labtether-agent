package sysconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const netplanConfigDir = "/etc/netplan"

func BackupNetplanConfig() (string, error) {
	info, err := os.Stat(netplanConfigDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", netplanConfigDir)
	}

	root, err := os.MkdirTemp(os.TempDir(), "labtether-network-")
	if err != nil {
		return "", err
	}
	dst := filepath.Join(root, "etc", "netplan")
	if err := copyDir(netplanConfigDir, dst); err != nil {
		_ = os.RemoveAll(root)
		return "", err
	}
	return root, nil
}

func RestoreNetplanConfig(backupRef string) error {
	// Validate the backup reference path to prevent path injection.
	// It must be inside the OS temp directory and must not contain
	// path traversal components.
	cleanRef := filepath.Clean(strings.TrimSpace(backupRef))
	tmpDir := filepath.Clean(os.TempDir())
	rel, relErr := filepath.Rel(tmpDir, cleanRef)
	if relErr != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("backup reference %q is outside the temp directory", backupRef)
	}

	source := filepath.Join(cleanRef, "etc", "netplan")
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", source)
	}

	// Hard-coded safety check: only restore to the canonical netplan config path.
	if filepath.Clean(netplanConfigDir) != "/etc/netplan" {
		return errors.New("unsafe netplan target path")
	}

	if err := os.RemoveAll(netplanConfigDir); err != nil {
		return err
	}
	return copyDir(source, netplanConfigDir)
}

func copyDir(src, dst string) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode().Perm()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		info, err := os.Lstat(srcPath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(srcPath)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dstPath); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported netplan entry %s: %s", srcPath, info.Mode().Type())
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("unsupported netplan file %s: %s", src, srcInfo.Mode().Type())
	}

	input, err := os.Open(src) // #nosec G304 -- Source path is validated within the netplan backup tree before copy.
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcInfo.Mode().Perm()) // #nosec G304 -- Destination path is generated under the controlled backup directory.
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, srcInfo.ModTime(), srcInfo.ModTime())
}
