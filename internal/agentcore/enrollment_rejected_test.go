package agentcore

import (
	"encoding/json"
	"testing"

	"github.com/labtether/protocol"
)

// After an admin rejected a pending device, the agent asked again within
// seconds and was back in Pending, so Reject did nothing. It must wait until
// it has an enrollment token, and say why in /agent/status.
func TestRejectedAgentWaitsForAToken(t *testing.T) {
	transport := &wsTransport{runtimeIdentity: newRuntimeIdentitySource(RuntimeConfig{})}
	data, _ := json.Marshal(protocol.EnrollmentRejectedData{Reason: "An admin rejected this device in LabTether."})
	handleEnrollmentRejected(transport, protocol.Message{Type: protocol.MsgEnrollmentRejected, Data: data})

	if !transport.waitingAfterRejection() {
		t.Fatal("a rejected agent without a token would ask again")
	}
	if got := transport.EnrollmentRefusal(); got != "An admin rejected this device in LabTether." {
		t.Fatalf("status reason %q", got)
	}
	transport.updateToken("new-enrollment-result")
	if transport.waitingAfterRejection() {
		t.Fatal("an agent with a token still waits")
	}
}
