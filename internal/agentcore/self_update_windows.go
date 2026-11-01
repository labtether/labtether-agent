//go:build windows

package agentcore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// stageExecutable writes the new binary beside the executable. The staged name
// keeps the .exe extension so the trial run can start it.
func stageExecutable(executablePath string, binary []byte) (string, error) {
	info, err := os.Stat(executablePath)
	if err != nil {
		return "", err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o755
	}

	base := strings.TrimSuffix(filepath.Base(executablePath), ".exe")
	newPath := filepath.Join(filepath.Dir(executablePath), fmt.Sprintf("%s.new-%d.exe", base, time.Now().UnixNano()))
	if err := os.WriteFile(newPath, binary, mode); err != nil {
		return "", fmt.Errorf("write new binary: %w", err)
	}
	return newPath, nil
}

// swapExecutable renames the running binary to <exe>.previous and the staged
// binary into its place. Windows cannot overwrite a running .exe, but it can
// rename one.
func swapExecutable(executablePath, stagedPath string) error {
	previous := executablePath + selfUpdatePreviousSuffix
	_ = os.Remove(previous)
	if err := os.Rename(executablePath, previous); err != nil {
		return fmt.Errorf("rename current to previous: %w", err)
	}
	if err := os.Rename(stagedPath, executablePath); err != nil {
		_ = os.Rename(previous, executablePath) // try to restore
		return fmt.Errorf("rename new to current: %w", err)
	}
	return nil
}

// restorePreviousExecutable moves the running (failed) binary aside and puts
// the kept binary back in its place.
func restorePreviousExecutable(executablePath, previous string) error {
	failed := fmt.Sprintf("%s.failed-%d", executablePath, time.Now().UnixNano())
	if err := os.Rename(executablePath, failed); err != nil {
		return fmt.Errorf("move failed binary aside: %w", err)
	}
	if err := os.Rename(previous, executablePath); err != nil {
		_ = os.Rename(failed, executablePath)
		return fmt.Errorf("restore previous binary: %w", err)
	}
	return nil
}
