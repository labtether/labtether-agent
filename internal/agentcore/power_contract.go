package agentcore

import (
	"fmt"
	"strings"
)

// These narrow declarations mirror github.com/labtether/protocol's typed
// power.action/power.result contract. The agent remains independently
// buildable against the published protocol v1.4.0 module until a newer
// protocol tag is released.
const (
	msgPowerAction = "power.action"
	msgPowerResult = "power.result"
)

type powerAction string

const (
	powerActionReboot   powerAction = "reboot"
	powerActionShutdown powerAction = "shutdown"
)

func (a powerAction) valid() bool {
	switch a {
	case powerActionReboot, powerActionShutdown:
		return true
	default:
		return false
	}
}

type powerResultStatus string

const (
	powerResultAccepted    powerResultStatus = "accepted"
	powerResultUnsupported powerResultStatus = "unsupported"
	powerResultRejected    powerResultStatus = "rejected"
	powerResultFailed      powerResultStatus = "failed"
)

type powerResultCode string

const (
	powerResultCodeInvalidRequest      powerResultCode = "invalid_request"
	powerResultCodeAssetMismatch       powerResultCode = "asset_mismatch"
	powerResultCodeCapabilityDenied    powerResultCode = "capability_denied"
	powerResultCodeBusy                powerResultCode = "busy"
	powerResultCodeUnsupportedPlatform powerResultCode = "unsupported_platform"
	powerResultCodeExecutionFailed     powerResultCode = "execution_failed"
	powerResultCodeExecutionTimeout    powerResultCode = "execution_timeout"
)

type powerActionData struct {
	RequestID string      `json:"request_id"`
	AssetID   string      `json:"asset_id"`
	Action    powerAction `json:"action"`
}

func (d powerActionData) validate() error {
	if strings.TrimSpace(d.RequestID) == "" || len(d.RequestID) > 128 {
		return fmt.Errorf("invalid request_id")
	}
	if strings.TrimSpace(d.AssetID) == "" || len(d.AssetID) > 256 {
		return fmt.Errorf("invalid asset_id")
	}
	if !d.Action.valid() {
		return fmt.Errorf("invalid action")
	}
	return nil
}

type powerResultData struct {
	RequestID string            `json:"request_id"`
	AssetID   string            `json:"asset_id"`
	Action    powerAction       `json:"action"`
	Status    powerResultStatus `json:"status"`
	Code      powerResultCode   `json:"code,omitempty"`
	Message   string            `json:"message,omitempty"`
}
