//go:build !windows

package agentcore

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// stageExecutable writes the new binary beside the executable with the same
// mode, ready for a trial run and an atomic rename.
func stageExecutable(executablePath string, binary []byte) (string, error) {
	info, err := os.Stat(executablePath)
	if err != nil {
		return "", err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o755
	}

	tmpPath := filepath.Join(filepath.Dir(executablePath), fmt.Sprintf(".%s.update-%d", filepath.Base(executablePath), time.Now().UnixNano()))
	if err := os.WriteFile(tmpPath, binary, mode); err != nil {
		return "", err
	}
	return tmpPath, nil
}

// swapExecutable keeps the running binary as <exe>.previous (a hard link, or a
// copy where links are unsupported) and renames the staged binary over it.
func swapExecutable(executablePath, stagedPath string) error {
	previous := executablePath + selfUpdatePreviousSuffix
	_ = os.Remove(previous)
	if err := os.Link(executablePath, previous); err != nil {
		if copyErr := copyExecutable(executablePath, previous); copyErr != nil {
			log.Printf("self-update: could not keep the previous binary; automatic rollback is off for this update: %v", copyErr)
		}
	}
	return os.Rename(stagedPath, executablePath)
}

func copyExecutable(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(source) // #nosec G304 -- Source is this agent's own executable path.
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, info.Mode().Perm())
}

// restorePreviousExecutable atomically renames the kept binary back. The
// running process keeps its own file until it exits.
func restorePreviousExecutable(executablePath, previous string) error {
	return os.Rename(previous, executablePath)
}
