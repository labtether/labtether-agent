package sysconfig

import (
	"errors"
	"fmt"
	"strings"

	"github.com/labtether/protocol"
)

var ResolveNetworkMethodFn = ResolveNetworkMethod
var BackupNetplanConfigFn = BackupNetplanConfig
var RestoreNetplanConfigFn = RestoreNetplanConfig
var VerifyNetworkConnectivity = VerifyConnectivity
var CollectActiveNMConnectionsFn = CollectActiveNMConnections
var ActivateNMConnectionsFn = ActivateNMConnections

// CaptureNetplanBaseline must run before an operator stages each set of edits.
// ApplyActionLinux fails closed without this explicit snapshot.
func (nm *NetworkManager) CaptureNetplanBaseline() error {
	nm.actionMu.Lock()
	defer nm.actionMu.Unlock()
	ref, err := BackupNetplanConfigFn()
	if err != nil {
		return err
	}
	nm.mu.Lock()
	nm.NetplanBaseline = ref
	nm.LastMethod = ""
	nm.LastNetplanBackup = ""
	nm.LastAppliedNetplan = ""
	nm.mu.Unlock()
	return nil
}

func (nm *NetworkManager) ApplyActionLinux(req protocol.NetworkActionData) protocol.NetworkResultData {
	nm.actionMu.Lock()
	defer nm.actionMu.Unlock()
	result := protocol.NetworkResultData{RequestID: req.RequestID}

	method, err := ResolveNetworkMethodFn(req.Method)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if err := requireConnectivityProbe(); err != nil {
		result.Error = err.Error()
		return result
	}

	switch method {
	case "netplan":
		nm.mu.Lock()
		backupRef := strings.TrimSpace(nm.NetplanBaseline)
		nm.mu.Unlock()
		if backupRef == "" {
			result.Error = "no pre-change netplan snapshot is available; save a snapshot before editing network files"
			return result
		}
		stagedRef, backupErr := BackupNetplanConfigFn()
		if backupErr != nil {
			result.Error = fmt.Sprintf("failed to snapshot staged netplan configuration: %v", backupErr)
			return result
		}
		result.RollbackReference = backupRef

		nm.mu.Lock()
		nm.LastMethod = "netplan"
		nm.LastNetplanBackup = backupRef
		nm.LastAppliedNetplan = stagedRef
		nm.NetplanBaseline = ""
		nm.LastNMConnections = nil
		nm.mu.Unlock()

		out, runErr := NetworkRunCommandWithTimeout(NetworkActionCommandTimeout, "netplan", "apply")
		result.Output = TruncateCommandOutput(out, MaxCommandOutputBytes)
		if runErr != nil {
			rollbackOutput, rollbackErr := nm.rollbackNetplan(stagedRef)
			result.RollbackAttempted = true
			result.RollbackOutput = rollbackOutput
			result.RollbackSucceeded = rollbackErr == nil
			if rollbackErr != nil {
				result.Error = fmt.Sprintf("netplan apply failed (%v); rollback failed: %v", runErr, rollbackErr)
				return result
			}
			result.Error = fmt.Sprintf("netplan apply failed (%v); rollback applied", runErr)
			return result
		}

		if verifyErr := VerifyNetworkConnectivity(req.VerifyTarget); verifyErr != nil {
			rollbackOutput, rollbackErr := nm.rollbackNetplan(stagedRef)
			result.RollbackAttempted = true
			result.RollbackOutput = rollbackOutput
			result.RollbackSucceeded = rollbackErr == nil
			if rollbackErr != nil {
				result.Error = fmt.Sprintf("connectivity verification failed (%v); rollback failed: %v", verifyErr, rollbackErr)
				return result
			}
			result.Error = fmt.Sprintf("connectivity verification failed (%v); rollback applied", verifyErr)
			return result
		}

		result.OK = true
		return result
	case "nmcli":
		active, activeErr := CollectActiveNMConnectionsFn()
		if activeErr != nil {
			result.Error = fmt.Sprintf("failed to snapshot active network connections: %v", activeErr)
			return result
		}

		nm.mu.Lock()
		nm.LastMethod = "nmcli"
		nm.LastNMConnections = CloneStringSlice(active)
		nm.LastNetplanBackup = ""
		nm.mu.Unlock()

		nmcliArgs := []string{"connection", "reload"}
		if connection := strings.TrimSpace(req.Connection); connection != "" {
			nmcliArgs = []string{"connection", "up", connection}
		}
		out, runErr := NetworkRunCommandWithTimeout(NetworkActionCommandTimeout, "nmcli", nmcliArgs...)
		result.Output = TruncateCommandOutput(out, MaxCommandOutputBytes)
		if runErr != nil {
			result.Error = fmt.Sprintf("nmcli %s failed: %v", strings.Join(nmcliArgs, " "), runErr)
			return result
		}

		if verifyErr := VerifyNetworkConnectivity(req.VerifyTarget); verifyErr != nil {
			rollbackOutput, rollbackErr := nm.rollbackNMCLI()
			result.RollbackAttempted = true
			result.RollbackOutput = rollbackOutput
			result.RollbackSucceeded = rollbackErr == nil
			if rollbackErr != nil {
				result.Error = fmt.Sprintf("connectivity verification failed (%v); rollback failed: %v", verifyErr, rollbackErr)
				return result
			}
			result.Error = fmt.Sprintf("connectivity verification failed (%v); rollback applied", verifyErr)
			return result
		}

		result.OK = true
		return result
	default:
		result.Error = fmt.Sprintf("unsupported method %q", method)
		return result
	}
}

func (nm *NetworkManager) RollbackActionLinux(req protocol.NetworkActionData) protocol.NetworkResultData {
	nm.actionMu.Lock()
	defer nm.actionMu.Unlock()
	result := protocol.NetworkResultData{RequestID: req.RequestID}

	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method == "" || method == "auto" {
		nm.mu.Lock()
		method = nm.LastMethod
		nm.mu.Unlock()
	}
	if method == "" {
		result.Error = "no rollback snapshot is available yet"
		return result
	}

	result.RollbackAttempted = true

	switch method {
	case "netplan":
		nm.mu.Lock()
		appliedRef := nm.LastAppliedNetplan
		nm.mu.Unlock()
		output, err := nm.rollbackNetplan(appliedRef)
		result.RollbackOutput = output
		result.RollbackSucceeded = err == nil
		result.OK = err == nil
		if err != nil {
			result.Error = err.Error()
		}
		nm.mu.Lock()
		result.RollbackReference = nm.LastNetplanBackup
		nm.mu.Unlock()
		return result
	case "nmcli":
		output, err := nm.rollbackNMCLI()
		result.RollbackOutput = output
		result.RollbackSucceeded = err == nil
		result.OK = err == nil
		if err != nil {
			result.Error = err.Error()
		}
		return result
	default:
		result.Error = fmt.Sprintf("invalid rollback method %q", method)
		return result
	}
}

func (nm *NetworkManager) rollbackNetplan(appliedRef string) (string, error) {
	nm.mu.Lock()
	backupRef := strings.TrimSpace(nm.LastNetplanBackup)
	nm.mu.Unlock()

	if backupRef == "" {
		return "", errors.New("no netplan backup reference is available")
	}
	if strings.TrimSpace(appliedRef) == "" {
		return "", errors.New("no applied netplan snapshot is available for rollback")
	}
	if err := RestoreNetplanConfigFn(backupRef); err != nil {
		return "", fmt.Errorf("restore netplan backup: %w", err)
	}
	out, err := NetworkRunCommandWithTimeout(NetworkActionCommandTimeout, "netplan", "apply", "--state", appliedRef)
	output := TruncateCommandOutput(out, MaxCommandOutputBytes)
	if err != nil {
		return output, fmt.Errorf("netplan apply after restore failed: %w", err)
	}
	nm.mu.Lock()
	nm.NetplanBaseline = ""
	nm.mu.Unlock()
	return output, nil
}

func (nm *NetworkManager) rollbackNMCLI() (string, error) {
	nm.mu.Lock()
	connections := CloneStringSlice(nm.LastNMConnections)
	nm.mu.Unlock()

	if len(connections) == 0 {
		return "", errors.New("no active nmcli connection snapshot is available")
	}
	return ActivateNMConnectionsFn(connections)
}
