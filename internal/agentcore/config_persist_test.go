package agentcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadPersistedConfigRestoresEffectiveIntervalsAtStartup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".labtether")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	data, err := json.Marshal(appliedConfig{
		CollectIntervalSec:   30,
		HeartbeatIntervalSec: 60,
	})
	if err != nil {
		t.Fatalf("marshal applied config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, appliedConfigFile), data, 0o600); err != nil {
		t.Fatalf("write applied config: %v", err)
	}

	stateDir := t.TempDir()
	runtime := NewRuntime(RuntimeConfig{
		CollectInterval:      10 * time.Second,
		HeartbeatInterval:    20 * time.Second,
		AllowRemoteOverrides: true,
		TokenFilePath:        filepath.Join(stateDir, "agent-token"),
	}, nil, nil)

	loadPersistedConfig(runtime)

	// An upgrade moves the pre-2.0 home-folder file into the state folder.
	if _, err := os.Stat(filepath.Join(stateDir, appliedConfigFile)); err != nil {
		t.Fatalf("applied config not moved to the state folder: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, appliedConfigFile)); !os.IsNotExist(err) {
		t.Fatalf("home-folder applied config still there after the move, err=%v", err)
	}
	if got := runtime.collectIntervalOverride.Load(); got != 30 {
		t.Fatalf("collect override=%d, want 30", got)
	}
	if got := runtime.heartbeatIntervalOverride.Load(); got != 60 {
		t.Fatalf("heartbeat override=%d, want 60", got)
	}
	if runtime.cfg.CollectInterval != 30*time.Second {
		t.Fatalf("CollectInterval=%v, want 30s", runtime.cfg.CollectInterval)
	}
	if runtime.cfg.HeartbeatInterval != 60*time.Second {
		t.Fatalf("HeartbeatInterval=%v, want 60s", runtime.cfg.HeartbeatInterval)
	}
	if got := runtime.effectiveCollectIntervalSec(); got != 30 {
		t.Fatalf("effective collect=%d, want 30", got)
	}
	if got := runtime.effectiveHeartbeatIntervalSec(); got != 60 {
		t.Fatalf("effective heartbeat=%d, want 60", got)
	}
}

func TestPersistAppliedConfigRemovesStaleFileWhenOverridesCleared(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stateDir := t.TempDir()
	runtime := NewRuntime(RuntimeConfig{
		CollectInterval:   10 * time.Second,
		HeartbeatInterval: 20 * time.Second,
		TokenFilePath:     filepath.Join(stateDir, "agent-token"),
	}, nil, nil)
	runtime.collectIntervalOverride.Store(30)
	runtime.heartbeatIntervalOverride.Store(60)

	persistAppliedConfig(runtime)

	path := filepath.Join(stateDir, appliedConfigFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected applied config file: %v", err)
	}

	runtime.collectIntervalOverride.Store(0)
	runtime.heartbeatIntervalOverride.Store(0)
	persistAppliedConfig(runtime)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected applied config file to be removed, got err=%v", err)
	}
}

// "Let the Hub change settings" off in the Mac and Windows apps sets
// LABTETHER_ALLOW_REMOTE_OVERRIDES=false. A Hub push saved while it was on
// must not come back at the next start, from the state folder or from the
// pre-2.0 home-folder file.
func TestLoadPersistedConfigIgnoresHubOverridesWhenRemoteOverridesAreOff(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateDir := t.TempDir()
	data, err := json.Marshal(appliedConfig{CollectIntervalSec: 15, HeartbeatIntervalSec: 25})
	if err != nil {
		t.Fatalf("marshal applied config: %v", err)
	}
	legacyDir := filepath.Join(home, ".labtether")
	for _, dir := range []string{legacyDir, stateDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, appliedConfigFile), data, 0o600); err != nil {
			t.Fatalf("write applied config: %v", err)
		}
	}

	runtime := NewRuntime(RuntimeConfig{
		CollectInterval:      10 * time.Second,
		HeartbeatInterval:    20 * time.Second,
		AllowRemoteOverrides: false,
		TokenFilePath:        filepath.Join(stateDir, "agent-token"),
	}, nil, nil)

	loadPersistedConfig(runtime)

	if got := runtime.heartbeatIntervalOverride.Load(); got != 0 {
		t.Fatalf("heartbeat override=%d with remote overrides off, want 0", got)
	}
	if got := runtime.collectIntervalOverride.Load(); got != 0 {
		t.Fatalf("collect override=%d with remote overrides off, want 0", got)
	}
	if got := runtime.effectiveHeartbeatIntervalSec(); got != 20 {
		t.Fatalf("effective heartbeat=%d, want the agent's own 20", got)
	}
	if got := runtime.effectiveCollectIntervalSec(); got != 10 {
		t.Fatalf("effective collect=%d, want the agent's own 10", got)
	}
}
