package agentcore

import (
	"encoding/base64"
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/remoteaccess"
	"github.com/labtether/protocol"
)

func testCapabilityToken(t *testing.T, payload string) string {
	t.Helper()
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestCapabilityBearingTokenCannotUseTerminalThroughCommandDispatcher(t *testing.T) {
	token := testCapabilityToken(t, `{"capabilities":["agent.command.execute"]}`)
	required := requiredCapabilitiesForMessage(protocol.MsgTerminalStart)
	if len(required) == 0 {
		t.Fatal("terminal messages must require a capability")
	}
	checked, allowed := remoteaccess.TokenAllowsAnyCapability(token, required...)
	if !checked || allowed {
		t.Fatalf("command-only token must not authorize terminal access: checked=%v allowed=%v", checked, allowed)
	}
}

func TestCapabilityBearingTokenAllowsMatchingFileCapability(t *testing.T) {
	token := testCapabilityToken(t, `{"capabilities":["agent.files"]}`)
	checked, allowed := remoteaccess.TokenAllowsAnyCapability(
		token,
		requiredCapabilitiesForMessage(protocol.MsgFileRead)...,
	)
	if !checked || !allowed {
		t.Fatalf("matching file capability should be accepted: checked=%v allowed=%v", checked, allowed)
	}
}

func TestDockerEndpointTestRequiresDockerCapability(t *testing.T) {
	required := requiredCapabilitiesForMessage(protocol.MsgDockerEndpointTest)
	if len(required) == 0 {
		t.Fatal("Docker endpoint tests must require a capability")
	}

	dockerToken := testCapabilityToken(t, `{"capabilities":["agent.docker"]}`)
	checked, allowed := remoteaccess.TokenAllowsAnyCapability(dockerToken, required...)
	if !checked || !allowed {
		t.Fatalf("matching Docker capability should be accepted: checked=%v allowed=%v", checked, allowed)
	}

	terminalToken := testCapabilityToken(t, `{"capabilities":["agent.terminal"]}`)
	checked, allowed = remoteaccess.TokenAllowsAnyCapability(terminalToken, required...)
	if !checked || allowed {
		t.Fatalf("unrelated capability must not authorize Docker endpoint tests: checked=%v allowed=%v", checked, allowed)
	}
}
