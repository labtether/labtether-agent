package agentcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	"github.com/labtether/protocol"
)

const powerExecutionTimeout = 8 * time.Second

type powerMessageSender interface {
	Send(protocol.Message) error
	AssetID() string
}

func handlePowerAction(ctx context.Context, transport powerMessageSender, msg protocol.Message, backend powerBackend) {
	handlePowerActionWithTimeout(ctx, transport, msg, backend, powerExecutionTimeout)
}

func handlePowerActionWithTimeout(ctx context.Context, transport powerMessageSender, msg protocol.Message, backend powerBackend, timeout time.Duration) {
	if transport == nil {
		return
	}
	if timeout <= 0 {
		timeout = powerExecutionTimeout
	}
	requestID := strings.TrimSpace(msg.ID)
	if requestID == "" || len(requestID) > 128 {
		return
	}

	// Decode once permissively so a syntactically correlated request with an
	// unknown field can receive an explicit rejection, then decode strictly for
	// actual admission.
	var candidate powerActionData
	if err := json.Unmarshal(msg.Data, &candidate); err != nil || !candidate.Action.valid() {
		return
	}

	var action powerActionData
	if err := decodePowerActionStrict(msg.Data, &action); err != nil {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   transport.AssetID(),
			Action:    candidate.Action,
			Status:    powerResultRejected,
			Code:      powerResultCodeInvalidRequest,
			Message:   "invalid power action request",
		})
		return
	}
	if action.RequestID != requestID {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   transport.AssetID(),
			Action:    action.Action,
			Status:    powerResultRejected,
			Code:      powerResultCodeInvalidRequest,
			Message:   "power request correlation failed",
		})
		return
	}
	if err := action.validate(); err != nil {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   transport.AssetID(),
			Action:    action.Action,
			Status:    powerResultRejected,
			Code:      powerResultCodeInvalidRequest,
			Message:   "invalid power action request",
		})
		return
	}

	assetID := strings.TrimSpace(transport.AssetID())
	if assetID == "" || action.AssetID != assetID {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   assetID,
			Action:    action.Action,
			Status:    powerResultRejected,
			Code:      powerResultCodeAssetMismatch,
			Message:   "power action target does not match this agent",
		})
		return
	}
	if backend == nil || !backend.Supported(action.Action) {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   assetID,
			Action:    action.Action,
			Status:    powerResultUnsupported,
			Code:      powerResultCodeUnsupportedPlatform,
			Message:   "power actions are not supported on this platform",
		})
		return
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := backend.Execute(execCtx, action.Action)
	if err == nil {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   assetID,
			Action:    action.Action,
			Status:    powerResultAccepted,
			Message:   "operating system accepted power action",
		})
		return
	}
	if errors.Is(err, errPowerUnsupported) {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   assetID,
			Action:    action.Action,
			Status:    powerResultUnsupported,
			Code:      powerResultCodeUnsupportedPlatform,
			Message:   "power actions are not supported on this platform",
		})
		return
	}
	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		sendPowerResult(transport, powerResultData{
			RequestID: requestID,
			AssetID:   assetID,
			Action:    action.Action,
			Status:    powerResultFailed,
			Code:      powerResultCodeExecutionTimeout,
			Message:   "operating system power request timed out",
		})
		return
	}
	sendPowerResult(transport, powerResultData{
		RequestID: requestID,
		AssetID:   assetID,
		Action:    action.Action,
		Status:    powerResultFailed,
		Code:      powerResultCodeExecutionFailed,
		Message:   "operating system did not accept the power request",
	})
}

func sendPowerRejectionForMessage(transport powerMessageSender, msg protocol.Message, code powerResultCode, message string) {
	if transport == nil {
		return
	}
	requestID := strings.TrimSpace(msg.ID)
	if requestID == "" || len(requestID) > 128 {
		return
	}
	var candidate powerActionData
	if err := json.Unmarshal(msg.Data, &candidate); err != nil || !candidate.Action.valid() {
		return
	}
	sendPowerResult(transport, powerResultData{
		RequestID: requestID,
		AssetID:   transport.AssetID(),
		Action:    candidate.Action,
		Status:    powerResultRejected,
		Code:      code,
		Message:   message,
	})
}

func sendPowerResult(transport powerMessageSender, result powerResultData) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	if err := transport.Send(protocol.Message{
		Type: msgPowerResult,
		ID:   result.RequestID,
		Data: data,
	}); err != nil {
		log.Printf("agentws: failed to send typed power result: %v", err)
	}
}

func decodePowerActionStrict(raw []byte, dst *powerActionData) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("power action payload must contain exactly one object")
	}
	return nil
}
