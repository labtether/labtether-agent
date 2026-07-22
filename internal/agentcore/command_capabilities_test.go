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
