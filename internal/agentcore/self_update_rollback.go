package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// Rollback after a bad self-update:
//
//   - Before the swap, the downloaded binary must start and print its version.
//   - The swap keeps the running binary as <exe>.previous and records the new
//     version as pending in <exe>.update-state.
//   - The new binary clears the pending record after its first heartbeat
//     reaches the Hub.
//   - If it starts more than selfUpdateMaxUnhealthyStarts times, or runs for
//     selfUpdateHealthDeadline, without reaching the Hub, it restores the
//     previous binary, remembers the version as rejected, and exits so the
//     service manager starts the previous version again.
const (
	selfUpdatePreviousSuffix     = ".previous"
	selfUpdateStateSuffix        = ".update-state"
	selfUpdateMaxUnhealthyStarts = 3
	selfUpdateTrialTimeout       = 20 * time.Second
	maxSelfUpdateStateBytes      = 4 * 1024
)

var (
	selfUpdateHealthDeadline = 15 * time.Minute
	selfUpdateTrialRunFn     = trialRunStagedExecutable
	selfUpdateHealthy        atomic.Bool
	selfUpdateStateMu        sync.Mutex
)

type selfUpdateState struct {
	PendingVersion  string `json:"pending_version,omitempty"`
	Starts          int    `json:"starts,omitempty"`
	RejectedVersion string `json:"rejected_version,omitempty"`
}

func readSelfUpdateState(executablePath string) selfUpdateState {
	var state selfUpdateState
	raw, err := readBoundedRegularFile(executablePath+selfUpdateStateSuffix, maxSelfUpdateStateBytes)
	if err != nil {
		return state
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		log.Printf("self-update: ignoring unreadable update state: %v", err)
		return selfUpdateState{}
	}
	return state
}

func writeSelfUpdateState(executablePath string, state selfUpdateState) error {
	path := executablePath + selfUpdateStateSuffix
	if state == (selfUpdateState{}) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeManagedFileAtomic(path, raw, 0o600, false)
}

// installVerifiedExecutable stages a verified release binary, proves that it
// starts, then swaps it in while keeping the running binary for rollback.
func installVerifiedExecutable(executablePath string, binary []byte, version string) error {
	staged, err := stageExecutable(executablePath, binary)
	if err != nil {
		return err
	}
	if err := selfUpdateTrialRunFn(staged, version); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("new binary did not start: %w", err)
	}
	if err := swapExecutable(executablePath, staged); err != nil {
		_ = os.Remove(staged)
		return err
	}
	selfUpdateStateMu.Lock()
	defer selfUpdateStateMu.Unlock()
	state := readSelfUpdateState(executablePath)
	state.PendingVersion, state.Starts = version, 0
	if err := writeSelfUpdateState(executablePath, state); err != nil {
		log.Printf("self-update: could not record the pending update; automatic rollback is off for it: %v", err)
	}
	return nil
}

// trialRunStagedExecutable runs the staged binary's version command and
// requires it to exit cleanly and report the release version.
func trialRunStagedExecutable(stagedPath, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), selfUpdateTrialTimeout)
	defer cancel()
	// #nosec G204 -- Runs only the signature-verified binary this updater just staged beside the executable.
	cmd := exec.CommandContext(ctx, stagedPath, "--version")
	cmd.WaitDelay = time.Second
	output, err := securityruntime.CaptureOutput(cmd, 4096)
	if err != nil {
		return err
	}
	want := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(version), "v"), "V")
	if want != "" && !strings.Contains(string(output), want) {
		return fmt.Errorf("reported %q, want version %s", strings.TrimSpace(string(output)), version)
	}
	return nil
}

// rejectedSelfUpdateVersion returns an error when version was already rolled
// back on this host, so an unforced update does not reinstall it.
func rejectedSelfUpdateVersion(executablePath, version string) error {
	rejected := readSelfUpdateState(executablePath).RejectedVersion
	if rejected != "" && strings.EqualFold(rejected, strings.TrimSpace(version)) {
		return fmt.Errorf("version %s was rolled back on this host after it failed to reach the Hub; use a forced update to try it again", rejected)
	}
	return nil
}

// checkPendingSelfUpdate runs once at startup. It counts starts of a freshly
// installed binary and rolls back once too many have not reached the Hub. It
// reports whether the health deadline should be watched.
func checkPendingSelfUpdate() bool {
	executablePath, err := executablePathFn()
	if err != nil {
		return false
	}
	selfUpdateStateMu.Lock()
	state := readSelfUpdateState(executablePath)
	if state.PendingVersion == "" {
		selfUpdateStateMu.Unlock()
		return false
	}
	state.Starts++
	if state.Starts > selfUpdateMaxUnhealthyStarts {
		selfUpdateStateMu.Unlock()
		rollBackSelfUpdate(executablePath, fmt.Sprintf("version %s did not reach the Hub in %d starts", state.PendingVersion, state.Starts-1))
		return false
	}
	if err := writeSelfUpdateState(executablePath, state); err != nil {
		log.Printf("self-update: could not record start %d of version %s: %v", state.Starts, state.PendingVersion, err)
	}
	selfUpdateStateMu.Unlock()
	return true
}

// watchSelfUpdateHealth rolls back when the new binary keeps running but has
// not reached the Hub within the deadline.
func watchSelfUpdateHealth(ctx context.Context) {
	timer := time.NewTimer(selfUpdateHealthDeadline)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	if selfUpdateHealthy.Load() {
		return
	}
	executablePath, err := executablePathFn()
	if err != nil {
		return
	}
	rollBackSelfUpdate(executablePath, fmt.Sprintf("the new version did not reach the Hub within %s", selfUpdateHealthDeadline))
}

// confirmSelfUpdateHealthy clears the pending record once a heartbeat has
// reached the Hub. Only the first call does any work.
func confirmSelfUpdateHealthy() {
	if selfUpdateHealthy.Swap(true) {
		return
	}
	executablePath, err := executablePathFn()
	if err != nil {
		return
	}
	selfUpdateStateMu.Lock()
	defer selfUpdateStateMu.Unlock()
	state := readSelfUpdateState(executablePath)
	if state.PendingVersion == "" {
		return
	}
	log.Printf("self-update: version %s reached the Hub; keeping it", state.PendingVersion)
	if err := writeSelfUpdateState(executablePath, selfUpdateState{RejectedVersion: state.RejectedVersion}); err != nil {
		log.Printf("self-update: could not clear the pending update record: %v", err)
	}
}

// rollBackSelfUpdate restores <exe>.previous over the running binary and exits
// so the service manager starts the previous version.
func rollBackSelfUpdate(executablePath, reason string) {
	selfUpdateStateMu.Lock()
	defer selfUpdateStateMu.Unlock()
	state := readSelfUpdateState(executablePath)
	if state.PendingVersion == "" || selfUpdateHealthy.Load() {
		return
	}
	previous := executablePath + selfUpdatePreviousSuffix
	if _, err := os.Stat(previous); err != nil {
		log.Printf("self-update: %s, but no previous binary was kept; leaving this version in place", reason)
		_ = writeSelfUpdateState(executablePath, selfUpdateState{RejectedVersion: state.RejectedVersion})
		return
	}
	if err := restorePreviousExecutable(executablePath, previous); err != nil {
		log.Printf("self-update: %s, and restoring the previous binary failed: %v", reason, err)
		return
	}
	if err := writeSelfUpdateState(executablePath, selfUpdateState{RejectedVersion: state.PendingVersion}); err != nil {
		log.Printf("self-update: could not record rejected version %s: %v", state.PendingVersion, err)
	}
	log.Printf("self-update: %s; restored the previous binary and restarting", reason)
	agentExitFn(selfUpdateExitCode)
}
