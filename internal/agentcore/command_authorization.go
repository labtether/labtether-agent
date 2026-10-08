package agentcore

import (
	"github.com/labtether/protocol"
	"strings"
)

// inboundMessageAllowed limits tokenless WebSockets to the three hub-to-agent
// enrollment control messages required to complete or reject enrollment.
// Operational messages must never reach their handlers until a subsequent
// WebSocket has authenticated with the approved bearer token.
func inboundMessageAllowed(enrollmentPending bool, messageType string) bool {
	if !enrollmentPending {
		return true
	}
	switch messageType {
	case protocol.MsgEnrollmentChallenge, protocol.MsgEnrollmentApproved, protocol.MsgEnrollmentRejected:
		return true
	default:
		return false
	}
}

// requiredCapabilitiesForMessage maps privileged hub-to-agent operations to
// token claims. Opaque legacy agent tokens continue to be authenticated by the
// hub, while capability-bearing JWTs are constrained at the endpoint as a
// second authorization boundary.
func requiredCapabilitiesForMessage(messageType string) []string {
	switch {
	case messageType == protocol.MsgConfigUpdate || messageType == protocol.MsgAgentSettingsApply:
		return []string{"agent.settings.apply", "agent.settings", "settings.apply"}
	case strings.HasPrefix(messageType, "terminal."):
		return []string{"agent.terminal", "terminal.connect", "terminal"}
	case strings.HasPrefix(messageType, "desktop.") || strings.HasPrefix(messageType, "webrtc.") || strings.HasPrefix(messageType, "clipboard."):
		return []string{"agent.desktop", "desktop.connect", "desktop"}
	case strings.HasPrefix(messageType, "file."):
		return []string{"agent.files", "files.manage", "files"}
	case strings.HasPrefix(messageType, "ssh_key."):
		return []string{"agent.ssh_keys", "ssh_keys.manage", "ssh_keys"}
	case messageType == protocol.MsgWoLSend:
		return []string{"agent.network.manage", "network.manage", "agent.operations"}
	case messageType == msgPowerAction:
		return []string{"agent.power", "power.manage", "agent.operations"}
	case strings.HasPrefix(messageType, "process."):
		return []string{"agent.processes", "processes.manage", "agent.operations"}
	case strings.HasPrefix(messageType, "service."):
		return []string{"agent.services", "services.manage", "agent.operations"}
	case strings.HasPrefix(messageType, "network."):
		return []string{"agent.network", "network.manage", "agent.operations"}
	case strings.HasPrefix(messageType, "package.") || strings.HasPrefix(messageType, "update."):
		return []string{"agent.update.apply", "update.apply", "agent.update"}
	case strings.HasPrefix(messageType, "cron.") || strings.HasPrefix(messageType, "users.") || strings.HasPrefix(messageType, "disk.") || strings.HasPrefix(messageType, "journal."):
		return []string{"agent.inspect", "agent.operations", "operations.read"}
	case strings.HasPrefix(messageType, "docker."):
		return []string{"agent.docker", "docker.manage", "agent.operations"}
	case messageType == protocol.MsgWebServiceSync:
		return []string{"agent.services", "services.manage", "agent.operations"}
	default:
		return nil
	}
}
