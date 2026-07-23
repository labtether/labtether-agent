package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/labtether/protocol"
)

type dockerEndpointTestCaptureSender struct {
	assetID  string
	messages []protocol.Message
}

func (s *dockerEndpointTestCaptureSender) Send(msg protocol.Message) error {
	s.messages = append(s.messages, msg)
	return nil
}

func (s *dockerEndpointTestCaptureSender) AssetID() string {
	return s.assetID
}

func dockerEndpointTestMessage(t *testing.T, request protocol.DockerEndpointTestData) protocol.Message {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return protocol.Message{Type: protocol.MsgDockerEndpointTest, ID: request.RequestID, Data: data}
}

func decodeDockerEndpointTestResult(t *testing.T, sender *dockerEndpointTestCaptureSender) (protocol.Message, protocol.DockerEndpointTestResultData) {
	t.Helper()
	if len(sender.messages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(sender.messages))
	}
	msg := sender.messages[0]
	if msg.Type != protocol.MsgDockerEndpointTestResult {
		t.Fatalf("message type = %q, want %q", msg.Type, protocol.MsgDockerEndpointTestResult)
	}
	var result protocol.DockerEndpointTestResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("agent sent invalid result: %v (%+v)", err, result)
	}
	if msg.ID != result.RequestID {
		t.Fatalf("envelope id = %q, payload request id = %q", msg.ID, result.RequestID)
	}
	return msg, result
}

func TestHandleDockerEndpointTestClosedOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		probeErr   error
		wantStatus protocol.DockerEndpointTestStatus
		wantCode   protocol.DockerEndpointTestCode
	}{
		{name: "reachable", wantStatus: protocol.DockerEndpointTestStatusReachable},
		{name: "unreachable", probeErr: errors.New("dial failed with private details"), wantStatus: protocol.DockerEndpointTestStatusFailed, wantCode: protocol.DockerEndpointTestCodeUnreachable},
		{name: "timeout", probeErr: context.DeadlineExceeded, wantStatus: protocol.DockerEndpointTestStatusFailed, wantCode: protocol.DockerEndpointTestCodeTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := &dockerEndpointTestCaptureSender{assetID: "node-1"}
			request := protocol.DockerEndpointTestData{
				RequestID: "docker-test-1",
				AssetID:   "node-1",
				Endpoint:  "UNIX:///run/docker.sock",
			}
			var probedEndpoint string
			handleDockerEndpointTestWithProbe(context.Background(), sender, dockerEndpointTestMessage(t, request), func(_ context.Context, endpoint string) error {
				probedEndpoint = endpoint
				return tt.probeErr
			})
			_, result := decodeDockerEndpointTestResult(t, sender)
			if probedEndpoint != "unix:///run/docker.sock" {
				t.Fatalf("probe endpoint = %q, want normalized unix endpoint", probedEndpoint)
			}
			if result.Endpoint != probedEndpoint || result.Status != tt.wantStatus || result.Code != tt.wantCode {
				t.Fatalf("result = %+v, want status=%q code=%q endpoint=%q", result, tt.wantStatus, tt.wantCode, probedEndpoint)
			}
			if tt.probeErr != nil && result.Message == tt.probeErr.Error() {
				t.Fatal("raw probe error must not cross the wire")
			}
		})
	}
}

func TestHandleDockerEndpointTestRejectsInvalidAndMismatchedRequests(t *testing.T) {
	tests := []struct {
		name     string
		msg      protocol.Message
		wantCode protocol.DockerEndpointTestCode
	}{
		{
			name:     "malformed payload",
			msg:      protocol.Message{Type: protocol.MsgDockerEndpointTest, ID: "docker-test-1", Data: json.RawMessage(`{"request_id":`)},
			wantCode: protocol.DockerEndpointTestCodeInvalidRequest,
		},
		{
			name: "mismatched envelope",
			msg: func() protocol.Message {
				msg := dockerEndpointTestMessage(t, protocol.DockerEndpointTestData{RequestID: "payload-id", AssetID: "node-1", Endpoint: "/run/docker.sock"})
				msg.ID = "envelope-id"
				return msg
			}(),
			wantCode: protocol.DockerEndpointTestCodeInvalidRequest,
		},
		{
			name:     "unsafe endpoint",
			msg:      dockerEndpointTestMessage(t, protocol.DockerEndpointTestData{RequestID: "docker-test-1", AssetID: "node-1", Endpoint: "/run/docker.sock\nsecret"}),
			wantCode: protocol.DockerEndpointTestCodeInvalidRequest,
		},
		{
			name:     "asset mismatch",
			msg:      dockerEndpointTestMessage(t, protocol.DockerEndpointTestData{RequestID: "docker-test-1", AssetID: "node-2", Endpoint: "/run/docker.sock"}),
			wantCode: protocol.DockerEndpointTestCodeAssetMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := &dockerEndpointTestCaptureSender{assetID: "node-1"}
			probeCalled := false
			handleDockerEndpointTestWithProbe(context.Background(), sender, tt.msg, func(context.Context, string) error {
				probeCalled = true
				return nil
			})
			_, result := decodeDockerEndpointTestResult(t, sender)
			if probeCalled {
				t.Fatal("invalid request must not reach the Docker probe")
			}
			if result.Status != protocol.DockerEndpointTestStatusRejected || result.Code != tt.wantCode {
				t.Fatalf("result = %+v, want rejected/%s", result, tt.wantCode)
			}
			if tt.wantCode == protocol.DockerEndpointTestCodeInvalidRequest && result.Endpoint != "" {
				t.Fatalf("invalid input endpoint must not be echoed: %q", result.Endpoint)
			}
		})
	}
}

func TestSendDockerEndpointTestBusyReturnsBoundedTypedResult(t *testing.T) {
	sender := &dockerEndpointTestCaptureSender{assetID: "node-1"}
	request := protocol.DockerEndpointTestData{
		RequestID: "docker-test-1",
		AssetID:   "node-1",
		Endpoint:  "/run/docker.sock",
	}
	sendDockerEndpointTestBusy(sender, dockerEndpointTestMessage(t, request))
	_, result := decodeDockerEndpointTestResult(t, sender)
	if result.Status != protocol.DockerEndpointTestStatusRejected || result.Code != protocol.DockerEndpointTestCodeBusy {
		t.Fatalf("busy result = %+v", result)
	}
}

func TestDockerEndpointTestLoopbackHTTPRequiresExplicitOutboundOptIn(t *testing.T) {
	sender := &dockerEndpointTestCaptureSender{assetID: "node-1"}
	request := protocol.DockerEndpointTestData{
		RequestID: "docker-test-loopback",
		AssetID:   "node-1",
		Endpoint:  "http://127.0.0.1:2375/",
	}
	msg := dockerEndpointTestMessage(t, request)

	t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "false")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "false")
	_, rejected, ok := validateDockerEndpointTestRequest(sender, msg)
	if ok || rejected.Code != protocol.DockerEndpointTestCodeInvalidRequest || rejected.Endpoint != "" {
		t.Fatalf("loopback HTTP endpoint was not rejected safely by default: ok=%v result=%+v", ok, rejected)
	}

	t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	normalized, _, ok := validateDockerEndpointTestRequest(sender, msg)
	if !ok {
		t.Fatal("loopback HTTP endpoint should be accepted with both explicit outbound opt-ins")
	}
	if normalized.Endpoint != "http://127.0.0.1:2375" {
		t.Fatalf("normalized endpoint = %q, want http://127.0.0.1:2375", normalized.Endpoint)
	}
}
