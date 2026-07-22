package agentcore

import (
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
)

func TestRedactSensitiveAgentSettingValuesRemovesTURNPassword(t *testing.T) {
	input := map[string]string{
		sysconfig.SettingKeyWebRTCTURNPass: "must-not-echo",
		sysconfig.SettingKeyWebRTCTURNURL:  "turn:example.test",
	}
	redacted := redactSensitiveAgentSettingValues(input)
	if _, ok := redacted[sysconfig.SettingKeyWebRTCTURNPass]; ok {
		t.Fatal("TURN password was echoed in agent settings state")
	}
	if redacted[sysconfig.SettingKeyWebRTCTURNURL] != "turn:example.test" {
		t.Fatal("non-secret TURN URL was not preserved")
	}
	if input[sysconfig.SettingKeyWebRTCTURNPass] != "must-not-echo" {
		t.Fatal("redaction mutated the private runtime values")
	}
}
