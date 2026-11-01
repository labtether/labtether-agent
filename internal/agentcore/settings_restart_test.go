package agentcore

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// files_root_mode showed as applied at once while the file browser kept the
// old scope until a manual restart. It now switches the file manager live.
func TestFilesRootModeAppliesWhileRunning(t *testing.T) {
	runtime := newSettingsLifecycleRuntime(t, RuntimeConfig{AllowRemoteOverrides: true, FileRootMode: "home"})
	var scope string
	runtime.applyFileRootMode = func(mode string) { scope = mode }

	_, restartRequired, err := runtime.applyAgentSettings(map[string]string{SettingKeyFilesRootMode: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if scope != "full" || restartRequired {
		t.Fatalf("file manager scope = %q, restart_required = %v; want full applied live", scope, restartRequired)
	}
	if got := runtime.ReportedAgentSettings()[SettingKeyFilesRootMode]; got != "full" {
		t.Fatalf("reported files_root_mode = %q, want full", got)
	}
}

// A setting read only at start must not be reported as in use before the
// agent restarts, and the agent restarts once for it, never in a loop.
func TestRestartOnlySettingIsReportedTruthfullyAndRestartsOnce(t *testing.T) {
	originalDelay := settingsRestartDelay
	settingsRestartDelay = 0
	t.Cleanup(func() { settingsRestartDelay = originalDelay })
	runtime := newSettingsLifecycleRuntime(t, RuntimeConfig{
		AllowRemoteOverrides: true,
		DockerEnabled:        "auto",
		AgentSettingsPath:    filepath.Join(t.TempDir(), "agent-config.json"),
	})
	var restarts atomic.Int32
	runtime.restartAgent = func() error { restarts.Add(1); return nil }

	_, restartRequired, err := runtime.applyAgentSettings(map[string]string{SettingKeyDockerEnabled: "false"})
	if err != nil || !restartRequired {
		t.Fatalf("restart_required = %v, err = %v; want a restart for docker_enabled", restartRequired, err)
	}
	if got := runtime.ReportedAgentSettings()[SettingKeyDockerEnabled]; got != "auto" {
		t.Fatalf("reported docker_enabled = %q before restart, want the running value auto", got)
	}
	runtime.restartForSettings()
	runtime.restartForSettings() // the same values again must not restart twice
	deadline := time.Now().Add(2 * time.Second)
	for restarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if got := restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d, want exactly 1", got)
	}

	// Setting it back to the running value needs no restart.
	_, restartRequired, err = runtime.applyAgentSettings(map[string]string{SettingKeyDockerEnabled: "auto"})
	if err != nil || restartRequired {
		t.Fatalf("restart_required = %v, err = %v after returning to the running value", restartRequired, err)
	}
}
