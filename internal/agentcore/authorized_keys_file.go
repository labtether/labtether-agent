package agentcore

import (
	"fmt"
	"os"
	"path/filepath"
)

const authorizedKeysTempPattern = ".authorized_keys.labtether-tmp-*"

// writeAuthorizedKeys replaces authorized_keys through a temporary file in the
// same directory and a rename, so a crash leaves the old or the new file and
// never an empty one that locks the user out of SSH. The new file keeps the
// old file's mode and owner (Unix) or DACL (Windows, where
// administrators_authorized_keys must stay limited to Administrators and
// SYSTEM). A symlinked authorized_keys is updated at its target and stays a
// link. Callers hold hubSSHKeyMu.
func writeAuthorizedKeys(path string, content []byte) error {
	target, err := authorizedKeysTarget(path)
	if err != nil {
		return err
	}
	original, err := os.Stat(target)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect authorized_keys: %w", err)
	}
	if exists && !original.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular authorized_keys %s", target)
	}
	mode := os.FileMode(0o600)
	if exists {
		mode = original.Mode().Perm()
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, authorizedKeysTempPattern)
	if err != nil {
		return fmt.Errorf("failed to create authorized_keys temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath) // #nosec G703 -- Temp path comes from os.CreateTemp beside authorized_keys.
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("failed to set authorized_keys mode: %w", err)
	}
	if exists {
		if err := keepAuthorizedKeysAccess(original, target, tmp); err != nil {
			return fmt.Errorf("failed to keep authorized_keys owner and access: %w", err)
		}
	}
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to flush authorized_keys: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}
	if err := replaceManagedFile(tmpPath, target); err != nil {
		return fmt.Errorf("failed to replace authorized_keys: %w", err)
	}
	committed = true
	syncAuthorizedKeysDir(dir)
	return nil
}

// authorizedKeysTarget follows a symlinked authorized_keys to the file it
// names, matching what os.WriteFile did before, so the link is kept.
func authorizedKeysTarget(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve authorized_keys link: %w", err)
	}
	return target, nil
}
