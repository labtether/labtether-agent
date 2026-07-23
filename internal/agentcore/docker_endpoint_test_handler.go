package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
)

const (
	dockerEndpointTestTimeout = 5 * time.Second
)

type dockerEndpointTestSender interface {
	Send(protocol.Message) error
	AssetID() string
}

type dockerEndpointProbe func(context.Context, string) error

func handleDockerEndpointTest(ctx context.Context, transport dockerEndpointTestSender, msg protocol.Message) {
	handleDockerEndpointTestWithProbe(ctx, transport, msg, dockerpkg.CheckDockerEndpoint)
}

func handleDockerEndpointTestWithProbe(
	ctx context.Context,
	transport dockerEndpointTestSender,
	msg protocol.Message,
	probe dockerEndpointProbe,
) {
	request, result, ok := validateDockerEndpointTestRequest(transport, msg)
	if !ok {
		sendDockerEndpointTestResult(transport, msg.ID, result)
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, dockerEndpointTestTimeout)
	defer cancel()
	if probe == nil {
		probe = dockerpkg.CheckDockerEndpoint
	}
	err := probe(probeCtx, request.Endpoint)
	result.Endpoint = request.Endpoint
	switch {
	case err == nil:
		result.Status = protocol.DockerEndpointTestStatusReachable
		result.Code = ""
		result.Message = "Docker endpoint is reachable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(probeCtx.Err(), context.DeadlineExceeded), isDockerEndpointTimeout(err):
		result.Status = protocol.DockerEndpointTestStatusFailed
		result.Code = protocol.DockerEndpointTestCodeTimeout
		result.Message = "Docker endpoint test timed out"
	default:
		result.Status = protocol.DockerEndpointTestStatusFailed
		result.Code = protocol.DockerEndpointTestCodeUnreachable
		result.Message = "Docker endpoint is unreachable"
	}
	sendDockerEndpointTestResult(transport, msg.ID, result)
}

func sendDockerEndpointTestBusy(transport dockerEndpointTestSender, msg protocol.Message) {
	request, result, ok := validateDockerEndpointTestRequest(transport, msg)
	if ok {
		result.Endpoint = request.Endpoint
		result.Status = protocol.DockerEndpointTestStatusRejected
		result.Code = protocol.DockerEndpointTestCodeBusy
		result.Message = "another Docker endpoint test is already in progress"
	}
	sendDockerEndpointTestResult(transport, msg.ID, result)
}

func validateDockerEndpointTestRequest(
	transport dockerEndpointTestSender,
	msg protocol.Message,
) (protocol.DockerEndpointTestData, protocol.DockerEndpointTestResultData, bool) {
	currentAssetID := ""
	if transport != nil {
		currentAssetID = strings.TrimSpace(transport.AssetID())
	}
	envelopeID := strings.TrimSpace(msg.ID)
	result := protocol.DockerEndpointTestResultData{
		RequestID: envelopeID,
		AssetID:   currentAssetID,
		Status:    protocol.DockerEndpointTestStatusRejected,
		Code:      protocol.DockerEndpointTestCodeInvalidRequest,
		Message:   "invalid Docker endpoint test request",
	}

	var request protocol.DockerEndpointTestData
	if err := json.Unmarshal(msg.Data, &request); err != nil {
		return request, result, false
	}
	if err := request.Validate(); err != nil || request.RequestID != envelopeID {
		return request, result, false
	}

	result.RequestID = request.RequestID
	normalized, err := NormalizeAgentSettingValue(SettingKeyDockerEndpoint, request.Endpoint)
	if err != nil {
		return request, result, false
	}
	request.Endpoint = normalized
	result.Endpoint = normalized
	if currentAssetID == "" || request.AssetID != currentAssetID {
		result.Status = protocol.DockerEndpointTestStatusRejected
		result.Code = protocol.DockerEndpointTestCodeAssetMismatch
		result.Message = "Docker endpoint test asset does not match this agent"
		return request, result, false
	}
	return request, result, true
}

func sendDockerEndpointTestResult(
	transport dockerEndpointTestSender,
	envelopeID string,
	result protocol.DockerEndpointTestResultData,
) {
	if transport == nil {
		return
	}
	envelopeID = strings.TrimSpace(envelopeID)
	if envelopeID != result.RequestID || result.Validate() != nil {
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDockerEndpointTestResult,
		ID:   envelopeID,
		Data: data,
	})
}

func isDockerEndpointTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
