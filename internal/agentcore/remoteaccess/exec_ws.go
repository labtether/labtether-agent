package remoteaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/packagepolicy"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// UpdatePackageLookPath finds package-manager executables. It is overridable
// so manager detection can be verified without running an OS update.
var UpdatePackageLookPath = exec.LookPath

// UpdatePackageCommand is the package-manager invocation for update.request.
type UpdatePackageCommand struct {
	Name string
	Args []string
}

// ExecConfig contains the subset of runtime config needed by command/update handlers.
type ExecConfig struct {
	APIToken string // #nosec G117 -- Runtime API token, not a hardcoded credential.
}

// SelfUpdateFn is the signature for self-update logic, wired from root agentcore.
var SelfUpdateFn func(cfg ExecConfig, force bool) (updated bool, summary string, err error)

// SelfUpdateExitFn is called after a successful self-update to exit the process.
var SelfUpdateExitFn func(code int)

// SelfUpdateExitCode is the exit code used after self-update.
const SelfUpdateExitCode = 10

// HandleCommandRequest executes a command locally and sends the result back.
func HandleCommandRequest(transport MessageSender, msg protocol.Message, cfg ExecConfig) {
	var req protocol.CommandRequestData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("agentws: invalid command request: %v", err)
		return
	}
	if strings.TrimSpace(cfg.APIToken) == "" {
		sendCommandResult(transport, req, "failed", "remote command execution requires an authenticated agent token")
		return
	}
	if checked, allowed := TokenAllowsAnyCapability(cfg.APIToken,
		"agent.command.execute",
		"command.execute",
		"agent.command",
	); checked && !allowed {
		sendCommandResult(transport, req, "failed", "token does not include command execution capability")
		return
	}
	if err := securityruntime.ValidateShellCommand(req.Command); err != nil {
		sendCommandResult(transport, req, "failed", err.Error())
		return
	}

	timeout := remoteCommandTimeoutFromSeconds(req.Timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd, err := securityruntime.NewValidatedShellCommandContext(ctx, req.Command)
	if err != nil {
		log.Printf("agentws: command blocked by runtime policy: %v", err)
		sendCommandResult(transport, req, "failed", err.Error())
		return
	}
	output := securityruntime.NewCappedRetainingWriter(MaxCommandOutputBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	err = cmd.Run()

	// Force-kill if the process survived the context timeout.
	if ctx.Err() == context.DeadlineExceeded && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait() // Reap zombie.
	}

	status := "succeeded"
	outputStr := retainedCommandOutput(output)
	if ctx.Err() == context.DeadlineExceeded {
		status = "failed"
		if outputStr != "" {
			outputStr += "\nerror: command timed out"
		} else {
			outputStr = "command timed out"
		}
	} else if err != nil {
		status = "failed"
		if outputStr != "" {
			outputStr += "\nerror: " + err.Error()
		} else {
			outputStr = err.Error()
		}
	}

	sendCommandResult(transport, req, status, outputStr)
}

// HandleUpdateRequest executes a system update and reports progress/results.
func HandleUpdateRequest(transport MessageSender, msg protocol.Message, cfg ExecConfig) {
	var req protocol.UpdateRequestData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("agentws: invalid update request: %v", err)
		return
	}

	sendProgress := func(stage, message string) {
		data, _ := json.Marshal(protocol.UpdateProgressData{
			JobID:   req.JobID,
			Stage:   stage,
			Message: message,
		})
		_ = transport.Send(protocol.Message{Type: protocol.MsgUpdateProgress, ID: req.JobID, Data: data})
	}

	sendResult := func(status, output, errMsg string) {
		data, _ := json.Marshal(protocol.UpdateResultData{
			JobID:  req.JobID,
			Status: status,
			Output: output,
			Error:  errMsg,
		})
		_ = transport.Send(protocol.Message{Type: protocol.MsgUpdateResult, ID: req.JobID, Data: data})
	}
	if strings.TrimSpace(cfg.APIToken) == "" {
		sendResult("failed", "", "remote updates require an authenticated agent token")
		return
	}
	if checked, allowed := TokenAllowsAnyCapability(cfg.APIToken,
		"agent.update.apply",
		"update.apply",
		"agent.update",
	); checked && !allowed {
		sendResult("failed", "", "token does not include update execution capability")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != "self" && mode != "os_packages" {
		sendResult("failed", "", fmt.Sprintf("unsupported update mode %q", mode))
		return
	}
	if err := ValidateUpdatePackages(req.Packages); err != nil {
		sendResult("failed", "", err.Error())
		return
	}

	if mode == "self" {
		if req.Force {
			sendProgress("checking", "Checking for agent binary updates (force enabled)...")
		} else {
			sendProgress("checking", "Checking for agent binary updates...")
		}
		if SelfUpdateFn == nil {
			sendResult("failed", "", "self-update not available")
			return
		}
		updated, summary, err := SelfUpdateFn(cfg, req.Force)
		if err != nil {
			sendResult("failed", "", err.Error())
			return
		}
		if !updated {
			sendResult("succeeded", summary, "")
			return
		}
		sendResult("succeeded", summary, "")

		// Allow the result message to flush to the hub before process exit.
		if SelfUpdateExitFn != nil {
			go func() {
				time.Sleep(600 * time.Millisecond)
				SelfUpdateExitFn(SelfUpdateExitCode)
			}()
		}
		return
	}

	// Detect package manager.
	sendProgress("detecting", "Detecting package manager...")
	updateCommand, err := ResolveUpdatePackageCommand(req.Packages, UpdatePackageLookPath)
	if err != nil {
		sendResult("failed", "", "no supported package manager found")
		return
	}
	pkgCmd := updateCommand.Name
	pkgArgs := updateCommand.Args

	sendProgress("running", fmt.Sprintf("Running %s %s...", pkgCmd, strings.Join(pkgArgs, " ")))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd, err := securityruntime.NewCommandContext(ctx, pkgCmd, pkgArgs...)
	if err != nil {
		sendResult("failed", "", err.Error())
		return
	}
	// Prevent interactive prompts on Debian/Ubuntu (e.g. debconf dialogs
	// during package upgrades that would hang indefinitely on headless systems).
	if pkgCmd == "apt-get" {
		cmd.Env = append(cmd.Environ(), "DEBIAN_FRONTEND=noninteractive")
	}
	output := securityruntime.NewCappedRetainingWriter(MaxCommandOutputBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	err = cmd.Run()

	// Force-kill if the process survived the context timeout.
	if ctx.Err() == context.DeadlineExceeded && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait() // Reap zombie.
	}

	outputStr := retainedCommandOutput(output)

	if ctx.Err() == context.DeadlineExceeded {
		sendResult("failed", outputStr, "update timed out")
		return
	}
	if err != nil {
		sendResult("failed", outputStr, err.Error())
		return
	}

	sendResult("succeeded", outputStr, "")
}

// ResolveUpdatePackageCommand detects a supported package manager and builds
// its non-interactive update invocation. Keep the candidate order aligned with
// the Linux package backend, with Homebrew retained for macOS agents.
func ResolveUpdatePackageCommand(packages []string, lookPath func(string) (string, error)) (UpdatePackageCommand, error) {
	for _, manager := range []string{"apt-get", "dnf", "yum", "zypper", "pacman", "apk", "brew"} {
		if path, err := lookPath(manager); err == nil && path != "" {
			return BuildUpdatePackageCommand(manager, packages)
		}
	}
	return UpdatePackageCommand{}, fmt.Errorf("no supported package manager found")
}

// BuildUpdatePackageCommand returns a non-interactive update invocation for a
// previously detected package manager.
func BuildUpdatePackageCommand(manager string, packages []string) (UpdatePackageCommand, error) {
	normalizedPackages, err := packagepolicy.NormalizeAndValidate(packages)
	if err != nil {
		return UpdatePackageCommand{}, err
	}
	packages = normalizedPackages

	var args []string
	switch manager {
	case "apt-get":
		if len(packages) > 0 {
			args = append([]string{"-y", "install", "--"}, packages...)
		} else {
			args = []string{"-y", "upgrade"}
		}
	case "dnf", "yum":
		if len(packages) > 0 {
			args = append([]string{"-y", "install"}, packages...)
		} else {
			args = []string{"-y", "upgrade"}
		}
	case "zypper":
		if len(packages) > 0 {
			args = append([]string{"--non-interactive", "install"}, packages...)
		} else {
			args = []string{"--non-interactive", "update"}
		}
	case "pacman":
		if len(packages) > 0 {
			args = append([]string{"--noconfirm", "-S", "--"}, packages...)
		} else {
			args = []string{"--noconfirm", "-Syu"}
		}
	case "apk":
		if len(packages) > 0 {
			args = append([]string{"add", "--upgrade"}, packages...)
		} else {
			args = []string{"upgrade"}
		}
	case "brew":
		if len(packages) > 0 {
			args = append([]string{"install", "--"}, packages...)
		} else {
			args = []string{"upgrade"}
		}
	default:
		return UpdatePackageCommand{}, fmt.Errorf("unsupported package manager %q", manager)
	}
	return UpdatePackageCommand{Name: manager, Args: args}, nil
}

func sendCommandResult(transport MessageSender, req protocol.CommandRequestData, status, output string) {
	result := protocol.CommandResultData{
		JobID:     req.JobID,
		SessionID: req.SessionID,
		CommandID: req.CommandID,
		Status:    status,
		Output:    output,
	}
	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		log.Printf("agentws: failed to marshal command result: %v", marshalErr)
		return
	}
	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgCommandResult,
		ID:   req.JobID,
		Data: data,
	}); sendErr != nil {
		log.Printf("agentws: failed to send command result for %s: %v", req.JobID, sendErr)
	}
}

func ValidateUpdatePackages(packages []string) error {
	_, err := packagepolicy.NormalizeAndValidate(packages)
	return err
}

func retainedCommandOutput(output *securityruntime.CappedRetainingWriter) string {
	retained := strings.TrimSpace(string(output.Bytes()))
	if output.Truncated() {
		retained += "\n...output truncated"
	}
	return retained
}

func TokenAllowsAnyCapability(token string, required ...string) (checked bool, allowed bool) {
	capabilities, ok := ExtractTokenCapabilities(token)
	if !ok {
		return false, true
	}
	for _, capability := range required {
		if _, exists := capabilities[strings.ToLower(strings.TrimSpace(capability))]; exists {
			return true, true
		}
	}
	return true, false
}

func ExtractTokenCapabilities(token string) (map[string]struct{}, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payloadRaw, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, false
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, false
	}

	out := make(map[string]struct{})
	collectClaimValues(payload["capabilities"], out)
	collectClaimValues(payload["capability"], out)
	collectClaimValues(payload["scope"], out)
	collectClaimValues(payload["scopes"], out)
	collectClaimValues(payload["scp"], out)
	collectClaimValues(payload["permissions"], out)
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func collectClaimValues(value any, out map[string]struct{}) {
	switch typed := value.(type) {
	case string:
		for _, capability := range splitCapabilityTokens(typed) {
			out[capability] = struct{}{}
		}
	case []any:
		for _, item := range typed {
			collectClaimValues(item, out)
		}
	case []string:
		for _, item := range typed {
			collectClaimValues(item, out)
		}
	}
}

func splitCapabilityTokens(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(parts) == 0 {
		return nil
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.ToLower(strings.TrimSpace(part))
		if normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}
