package agentcore

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

const appliedConfigFile = "applied-config.json"

type appliedConfig struct {
	CollectIntervalSec   int `json:"collect_interval_sec,omitempty"`
	HeartbeatIntervalSec int `json:"heartbeat_interval_sec,omitempty"`
}

// appliedConfigPath is applied-config.json in this agent's state folder,
// beside its token, so each agent instance keeps its own Hub overrides. An
// agent with no token path falls back to the pre-2.0 place in the home folder.
func appliedConfigPath(r *Runtime) string {
	r.mu.RLock()
	tokenFile := r.cfg.TokenFilePath
	r.mu.RUnlock()
	if dir := stateDirFor(tokenFile); dir != "" {
		return filepath.Join(dir, appliedConfigFile)
	}
	return legacyAppliedConfigPath()
}

// legacyAppliedConfigPath is where agents before 2.0 kept the file: the
// user's home folder, shared by every agent that user runs.
func legacyAppliedConfigPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, appliedConfigFile)
}

// persistAppliedConfig writes the current runtime overrides to disk.
func persistAppliedConfig(r *Runtime) {
	if r == nil {
		return
	}
	path := appliedConfigPath(r)
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	cfg := appliedConfig{
		CollectIntervalSec:   int(r.collectIntervalOverride.Load()),
		HeartbeatIntervalSec: int(r.heartbeatIntervalOverride.Load()),
	}
	if cfg.CollectIntervalSec == 0 && cfg.HeartbeatIntervalSec == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("config: failed to remove applied config: %v", err)
		}
		return
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("config: failed to create config dir: %v", err)
		return
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	if err := writeManagedFileAtomic(path, data, 0o600, true); err != nil {
		log.Printf("config: failed to persist applied config: %v", err)
	}
}

// loadPersistedConfig reads applied-config.json and restores the Hub's
// interval overrides to the runtime. With remote overrides off it restores
// nothing: the agent runs its own values. An upgraded agent with overrides
// on reads the pre-2.0 home-folder file once and moves it to its state folder.
func loadPersistedConfig(r *Runtime) {
	if r == nil {
		return
	}
	path := appliedConfigPath(r)
	if path == "" {
		return
	}
	if !r.allowRemoteOverrides() {
		if _, err := os.Stat(path); err == nil {
			log.Printf("config: remote overrides are off; the Hub's saved intervals in %s are not applied", path)
		}
		return
	}
	legacy := ""
	data, err := readBoundedRegularFile(path, maxAppliedConfigBytes)
	if err != nil {
		legacy = legacyAppliedConfigPath()
		if legacy == "" || legacy == path {
			return
		}
		if data, err = readBoundedRegularFile(legacy, maxAppliedConfigBytes); err != nil {
			return // no saved overrides
		}
	}
	defer func() {
		if legacy == "" {
			return
		}
		persistAppliedConfig(r)
		if _, statErr := os.Stat(path); statErr == nil {
			if rmErr := os.Remove(legacy); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("config: failed to remove %s after moving it: %v", legacy, rmErr)
			}
		}
	}()
	var cfg appliedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("config: failed to parse applied config: %v", err)
		return
	}
	if cfg.CollectIntervalSec >= 2 && cfg.CollectIntervalSec <= 300 && !r.cfg.settingPinned(SettingKeyCollectIntervalSec) {
		r.collectIntervalOverride.Store(int64(cfg.CollectIntervalSec))
		r.mu.Lock()
		r.cfg.CollectInterval = time.Duration(cfg.CollectIntervalSec) * time.Second
		r.mu.Unlock()
		log.Printf("config: restored collect interval override: %ds", cfg.CollectIntervalSec)
	}
	if cfg.HeartbeatIntervalSec >= 5 && cfg.HeartbeatIntervalSec <= 600 && !r.cfg.settingPinned(SettingKeyHeartbeatIntervalSec) {
		r.heartbeatIntervalOverride.Store(int64(cfg.HeartbeatIntervalSec))
		r.mu.Lock()
		r.cfg.HeartbeatInterval = time.Duration(cfg.HeartbeatIntervalSec) * time.Second
		r.mu.Unlock()
		log.Printf("config: restored heartbeat interval override: %ds", cfg.HeartbeatIntervalSec)
	}
}

// configDir returns the directory for persisted agent config.
func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".labtether")
}
