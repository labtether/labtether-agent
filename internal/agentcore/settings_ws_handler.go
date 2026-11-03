package agentcore

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/labtether/protocol"
)

// handleConfigUpdate applies runtime configuration changes from the hub.
func handleConfigUpdate(transport agentMessageSender, msg protocol.Message, runtime *Runtime) {
	var data protocol.ConfigUpdateData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("agentws: invalid config update: %v", err)
		return
	}

	log.Printf("agentws: received config update: collect=%s heartbeat=%s loglevel=%s",
		configUpdateValue(data.CollectIntervalSec), configUpdateValue(data.HeartbeatIntervalSec), configUpdateValue(data.LogLevel))

	if runtime == nil {
		return
	}
	if !runtime.allowRemoteOverrides() {
		log.Printf("agentws: ignoring config update because remote overrides are disabled")
		sendLegacyConfigApplied(transport, runtime)
		return
	}
	if data.CollectIntervalSec != nil && runtime.cfg.settingPinned(SettingKeyCollectIntervalSec) {
		log.Printf("agentws: keeping the install-time collect interval")
		data.CollectIntervalSec = nil
	}
	if data.HeartbeatIntervalSec != nil && runtime.cfg.settingPinned(SettingKeyHeartbeatIntervalSec) {
		log.Printf("agentws: keeping the install-time heartbeat interval")
		data.HeartbeatIntervalSec = nil
	}

	changed := false
	if data.CollectIntervalSec != nil {
		v := *data.CollectIntervalSec
		switch {
		case v == 0:
			runtime.collectIntervalOverride.Store(0)
			runtime.mu.Lock()
			runtime.cfg.CollectInterval = runtime.baseCollectInterval
			runtime.mu.Unlock()
			changed = true
		case v >= 2 && v <= 300:
			runtime.collectIntervalOverride.Store(int64(v))
			runtime.mu.Lock()
			runtime.cfg.CollectInterval = time.Duration(v) * time.Second
			runtime.mu.Unlock()
			changed = true
		default:
			log.Printf("agentws: ignoring invalid collect interval %d (must be 2-300)", v)
		}
	}
	if data.HeartbeatIntervalSec != nil {
		v := *data.HeartbeatIntervalSec
		switch {
		case v == 0:
			runtime.heartbeatIntervalOverride.Store(0)
			runtime.mu.Lock()
			runtime.cfg.HeartbeatInterval = runtime.baseHeartbeatInterval
			runtime.mu.Unlock()
			changed = true
		case v >= 5 && v <= 600:
			runtime.heartbeatIntervalOverride.Store(int64(v))
			runtime.mu.Lock()
			runtime.cfg.HeartbeatInterval = time.Duration(v) * time.Second
			runtime.mu.Unlock()
			changed = true
		default:
			log.Printf("agentws: ignoring invalid heartbeat interval %d (must be 5-600)", v)
		}
	}

	if changed {
		// Persist applied config to disk.
		persistAppliedConfig(runtime)
	}

	// Send acknowledgment back to hub.
	sendLegacyConfigApplied(transport, runtime)
}

func sendLegacyConfigApplied(transport agentMessageSender, runtime *Runtime) {
	ackData, _ := json.Marshal(protocol.ConfigAppliedData{
		CollectIntervalSec:   runtime.effectiveCollectIntervalSec(),
		HeartbeatIntervalSec: runtime.effectiveHeartbeatIntervalSec(),
	})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgConfigApplied,
		Data: ackData,
	})
}

func handleAgentSettingsApply(transport agentMessageSender, msg protocol.Message, runtime *Runtime) {
	var req protocol.AgentSettingsApplyData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("agentws: invalid agent.settings.apply: %v", err)
		return
	}

	response := protocol.AgentSettingsAppliedData{
		RequestID: req.RequestID,
		Revision:  req.Revision,
		Applied:   false,
	}

	if runtime == nil {
		response.Error = "runtime unavailable"
		sendAgentSettingsApplied(transport, runtime, response)
		return
	}

	if !runtime.allowRemoteOverrides() {
		response.Error = "remote overrides are disabled on this agent"
		sendAgentSettingsApplied(transport, runtime, response)
		sendAgentSettingsState(transport, runtime, req.Revision)
		return
	}

	if runtime.deviceIdentity != nil && strings.TrimSpace(req.ExpectedFingerprint) != "" &&
		!strings.EqualFold(strings.TrimSpace(req.ExpectedFingerprint), runtime.deviceIdentity.Fingerprint) {
		response.Error = "fingerprint mismatch for settings apply"
		sendAgentSettingsApplied(transport, runtime, response)
		sendAgentSettingsState(transport, runtime, req.Revision)
		return
	}

	applied, restartRequired, err := runtime.applyAgentSettings(req.Values)
	if err != nil {
		response.Error = err.Error()
		sendAgentSettingsApplied(transport, runtime, response)
		sendAgentSettingsState(transport, runtime, req.Revision)
		return
	}

	response.Applied = true
	response.RestartRequired = restartRequired
	response.AppliedValues = redactSensitiveAgentSettingValues(applied)
	response.AppliedAt = time.Now().UTC().Format(time.RFC3339)
	sendAgentSettingsApplied(transport, runtime, response)
	sendAgentSettingsState(transport, runtime, req.Revision)
	if restartRequired {
		runtime.restartForSettings()
	}
}

func sendAgentSettingsApplied(transport agentMessageSender, runtime *Runtime, response protocol.AgentSettingsAppliedData) {
	if runtime != nil && runtime.deviceIdentity != nil {
		response.Fingerprint = runtime.deviceIdentity.Fingerprint
	}
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("agentws: failed to marshal agent.settings.applied: %v", err)
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgAgentSettingsApplied,
		Data: data,
	})
}

// configUpdateValue prints a config update field for the log: its value, or
// "unchanged" when the Hub did not send it. Printing the pointer itself gave
// lines like "collect=0x6f6bd1903f8".
func configUpdateValue[T any](value *T) string {
	if value == nil {
		return "unchanged"
	}
	return fmt.Sprint(*value)
}
