package agentcore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func stubSelfUpdateTrialRun(t *testing.T) {
	t.Helper()
	original := selfUpdateTrialRunFn
	selfUpdateTrialRunFn = func(string, string) error { return nil }
	t.Cleanup(func() { selfUpdateTrialRunFn = original })
}

func useTestExecutable(t *testing.T, content string) string {
	t.Helper()
	executablePath := filepath.Join(t.TempDir(), "labtether-agent")
	if err := os.WriteFile(executablePath, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	original := executablePathFn
	executablePathFn = func() (string, error) { return executablePath, nil }
	t.Cleanup(func() { executablePathFn = original })
	return executablePath
}

func readTestExecutable(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executable: %v", err)
	}
	return string(content)
}

// One bad signed release must not keep agents offline until a manual
// reinstall: after repeated starts that never reach the Hub, the previous
// binary comes back and unforced updates skip that version.
func TestSelfUpdateRollsBackAfterRepeatedUnhealthyStarts(t *testing.T) {
	stubSelfUpdateTrialRun(t)
	selfUpdateHealthy.Store(false)
	t.Cleanup(func() { selfUpdateHealthy.Store(false) })
	executablePath := useTestExecutable(t, "old-binary")
	exitCode := 0
	originalExit := agentExitFn
	agentExitFn = func(code int) { exitCode = code }
	t.Cleanup(func() { agentExitFn = originalExit })

	if err := installVerifiedExecutable(executablePath, []byte("new-binary"), "v2.0.0"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if got := readTestExecutable(t, executablePath); got != "new-binary" {
		t.Fatalf("installed executable = %q", got)
	}
	for start := 1; start <= selfUpdateMaxUnhealthyStarts; start++ {
		if !checkPendingSelfUpdate() {
			t.Fatalf("start %d did not watch the pending update", start)
		}
	}
	if checkPendingSelfUpdate() || exitCode != selfUpdateExitCode {
		t.Fatalf("no rollback after %d unhealthy starts (exit code %d)", selfUpdateMaxUnhealthyStarts, exitCode)
	}
	if got := readTestExecutable(t, executablePath); got != "old-binary" {
		t.Fatalf("executable after rollback = %q, want the previous binary", got)
	}
	if err := rejectedSelfUpdateVersion(executablePath, "v2.0.0"); err == nil {
		t.Fatal("rolled-back version would be installed again")
	}
}

// A downloaded binary that cannot start is never swapped in.
func TestSelfUpdateKeepsBinaryWhenTrialRunFails(t *testing.T) {
	original := selfUpdateTrialRunFn
	selfUpdateTrialRunFn = func(string, string) error { return errors.New("exec format error") }
	t.Cleanup(func() { selfUpdateTrialRunFn = original })
	executablePath := useTestExecutable(t, "old-binary")

	if err := installVerifiedExecutable(executablePath, []byte("broken-binary"), "v2.0.0"); err == nil {
		t.Fatal("binary that failed its trial run was installed")
	}
	if got := readTestExecutable(t, executablePath); got != "old-binary" {
		t.Fatalf("executable = %q, want it unchanged", got)
	}
	entries, err := os.ReadDir(filepath.Dir(executablePath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("staged files left behind: %d entries", len(entries))
	}
}
