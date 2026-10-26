package agentcore

import (
	"encoding/json"
	"github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
	"testing"
	"time"
)

func TestReceiveLoopDispatchesComposeWireVersions(t *testing.T) {
	collector := docker.NewDockerCollector("https://docker.example:2376?unsupported=1", nil, "host", time.Minute)
	_, server, stop := startReceiveLoopForEnrollmentTest(t, false, collector)
	defer stop()
	for _, test := range []struct{ name, kind, want string }{
		{"v2", protocol.MsgDockerComposeActionV2, "Compose endpoint changed or missing; refresh and resubmit the action"},
		{"legacy", protocol.MsgDockerComposeAction, "Docker endpoint cannot be represented by Compose"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := json.Marshal(protocol.DockerComposeActionData{RequestID: test.name, StackName: "project", Action: "restart"})
			if err != nil {
				t.Fatal(err)
			}
			if err := server.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := server.WriteJSON(protocol.Message{Type: test.kind, Data: request}); err != nil {
				t.Fatal(err)
			}
			if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var message protocol.Message
			if err := server.ReadJSON(&message); err != nil {
				t.Fatal(err)
			}
			var result protocol.DockerComposeResultData
			if message.Type != protocol.MsgDockerComposeResult || message.ID != test.name || json.Unmarshal(message.Data, &result) != nil || result.RequestID != test.name || result.Success || result.Output != "" || result.Error != test.want {
				t.Fatalf("Compose receiver contract: type=%q id=%q result=%+v", message.Type, message.ID, result)
			}
		})
	}
}
