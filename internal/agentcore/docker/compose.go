package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

var (
	dockerComposeCLIDetect         = isDockerComposeCLIAvailable
	dockerComposeNewCommandContext = securityruntime.NewCommandContext
)

const (
	composeActionTimeout     = 5 * time.Minute
	composeActionOutputLimit = 64 * 1024
)

// isDockerComposeCLIAvailable checks if docker compose (v2) or docker-compose (v1) is available.
func isDockerComposeCLIAvailable() (version int, available bool) {
	// Try docker compose v2 first
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := securityruntime.CommandContextCombinedOutput(ctx, "docker", "compose", "version"); err == nil {
		if strings.Contains(string(out), "Docker Compose") {
			return 2, true
		}
	}
	// Fall back to docker-compose v1
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return 1, true
	}
	return 0, false
}

// HandleComposeAction uses the collector's exact daemon for lookup and CLI dispatch.
func (dc *DockerCollector) HandleComposeAction(transport Transport, msg protocol.Message) {
	var req protocol.DockerComposeActionData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("docker-compose: invalid action payload: %v", err)
		return
	}
	var trust *composeTLSMaterial
	result := protocol.DockerComposeResultData{RequestID: req.RequestID}
	defer func() {
		if trust != nil && trust.close() != nil {
			result.Success = false
			result.Error = "Compose TLS trust file cleanup failed"
		}
		sendComposeResult(transport, req.RequestID, result.Success, result.Output, result.Error)
	}()
	fail := func(err error) { result.Error = err.Error() }
	if msg.Type == protocol.MsgDockerComposeActionV2 && (req.EndpointID != dc.composeEndpointID() || len(req.EndpointID) != 64) {
		fail(fmt.Errorf("Compose endpoint changed or missing; refresh and resubmit the action"))
		return
	}
	host, err := composeDaemonHost(dc.socketPath)
	if err != nil {
		fail(err)
		return
	}
	usesTLS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(dc.socketPath)), "https://")
	if !composeProjectName.MatchString(req.StackName) {
		fail(fmt.Errorf("invalid native Compose project name"))
		return
	}
	if req.Action != "up" && req.Action != "down" && req.Action != "restart" && req.Action != "pull" && req.Action != "deploy" {
		fail(fmt.Errorf("unsupported compose action"))
		return
	}
	parent := context.Background()
	if owner, ok := transport.(interface{ Context() context.Context }); ok {
		parent = owner.Context()
	}
	ctx, cancel := context.WithTimeout(parent, composeActionTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		fail(err)
		return
	}
	version, available := dockerComposeCLIDetect()
	if !available {
		fail(fmt.Errorf("docker compose CLI not available on this host"))
		return
	}
	if usesTLS {
		if version != 2 {
			fail(fmt.Errorf("%s", composeHTTPSUnsupported))
			return
		}
		trust, err = dc.prepareComposeTLS(ctx)
		if err != nil {
			fail(err)
			return
		}
	}
	var selected composeSelection
	if req.Action == "deploy" {
		selected, err = prepareComposeDeploy(ctx, req)
	} else {
		selected, err = dc.resolveComposeSelection(ctx, req, msg.Type == protocol.MsgDockerComposeActionV2)
	}
	if err != nil {
		fail(err)
		return
	}
	action := req.Action
	var extra []string
	if action == "deploy" || action == "up" {
		action = "up"
		extra = []string{"-d"}
	}
	cmdName, cmdArgs := composeCommandArgs(version, host, selected, action, extra...)
	if trust != nil {
		// These global Docker flags precede the Compose subcommand. Explicit empty
		// client paths suppress CLI defaults without changing registry credentials.
		cmdArgs = append(cmdArgs[:2:2], append(trust.flags(), cmdArgs[2:]...)...)
	}
	cmd, err := dockerComposeNewCommandContext(ctx, cmdName, cmdArgs...)
	if err != nil {
		fail(err)
		return
	}
	cmd.Dir = selected.Dir
	cmd.Env = composeEnvironment(securityruntime.SanitizedChildEnv(), host, selected.Name)
	// A descendant keeping inherited pipes open must not occupy this handler forever.
	// This bounds pipe draining; it does not claim descendant-tree termination.
	cmd.WaitDelay = time.Second
	outputCapture := securityruntime.NewCappedRetainingWriter(composeActionOutputLimit)
	cmd.Stdout, cmd.Stderr = outputCapture, outputCapture
	err = cmd.Run()
	output := strings.TrimSpace(string(outputCapture.Bytes()))
	if outputCapture.Truncated() {
		output += "\n...output truncated"
	}
	if err != nil {
		result.Output = output
		fail(err)
		return
	}
	dc.refreshDockerStateSoon()
	result.Success, result.Output = true, output
}

func prepareComposeDeploy(ctx context.Context, req protocol.DockerComposeActionData) (composeSelection, error) {
	selected := composeSelection{Name: req.StackName, Dir: req.ConfigDir}
	if strings.TrimSpace(req.ComposeYAML) == "" {
		return selected, fmt.Errorf("compose_yaml is required")
	}
	if selected.Dir == "" {
		selected.Dir = filepath.Join(os.TempDir(), "labtether-stacks", selected.Name)
	}
	if !filepath.IsAbs(selected.Dir) || strings.ContainsRune(selected.Dir, 0) {
		return selected, fmt.Errorf("config_dir must be an absolute local directory")
	}
	selected.Files = []string{filepath.Join(selected.Dir, "docker-compose.yml")}
	if len(req.ConfigFiles) != 0 && !stringSlicesEqual(selected.Files, req.ConfigFiles) {
		return selected, fmt.Errorf("deploy must select only its written Compose file")
	}
	if err := ctx.Err(); err != nil {
		return selected, err
	}
	if err := os.MkdirAll(selected.Dir, 0o750); err != nil {
		return selected, err
	}
	if err := os.WriteFile(selected.Files[0], []byte(req.ComposeYAML), 0o600); err != nil {
		return selected, err
	}
	return selected, nil
}

func sendComposeResult(transport Transport, requestID string, success bool, output, errMsg string) {
	result := protocol.DockerComposeResultData{
		RequestID: requestID,
		Success:   success,
		Output:    output,
		Error:     errMsg,
	}
	data, _ := json.Marshal(result)
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDockerComposeResult,
		ID:   requestID,
		Data: data,
	})
}
