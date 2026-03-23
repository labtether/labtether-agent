package agentcore

import (
	"encoding/json"
	"log"
	"time"

	"github.com/labtether/protocol"
)

func sendAgentSettingsState(transport *wsTransport, runtime *Runtime, revision string) {
	if transport == nil || runtime == nil || !transport.Connected() {
		return
	}

	fingerprint := ""
	if runtime.deviceIdentity != nil {
		fingerprint = runtime.deviceIdentity.Fingerprint
	}

	payload := protocol.AgentSettingsStateData{
		Revision:             revision,
		Values:               runtime.ReportedAgentSettings(),
		Fingerprint:          fingerprint,
		AllowRemoteOverrides: runtime.allowRemoteOverrides(),
		ReportedAt:           time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("agentws: failed to marshal agent.settings.state: %v", err)
		return
	}
	if err := transport.Send(protocol.Message{
		Type: protocol.MsgAgentSettingsState,
		Data: data,
	}); err != nil {
		log.Printf("agentws: failed to send agent.settings.state: %v", err)
	}
}
