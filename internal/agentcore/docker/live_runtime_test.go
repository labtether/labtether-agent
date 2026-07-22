package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// TestLiveDockerRuntimeLifecycle is an opt-in installed-runtime check against a
// real Docker Engine. It uses one uniquely named disposable container and
// removes only that exact container. Normal unit and CI runs skip it.
func TestLiveDockerRuntimeLifecycle(t *testing.T) {
	if os.Getenv("LABTETHER_LIVE_DOCKER_QA") != "1" {
		t.Skip("set LABTETHER_LIVE_DOCKER_QA=1 to exercise a real Docker Engine")
	}

	endpoint := strings.TrimSpace(os.Getenv("LABTETHER_DOCKER_QA_ENDPOINT"))
	if endpoint == "" {
		endpoint = "/var/run/docker.sock"
	}
	image := strings.TrimSpace(os.Getenv("LABTETHER_DOCKER_QA_IMAGE"))
	if image == "" {
		image = "alpine:3.22"
	}
	name := fmt.Sprintf("ltqa-agent-docker-%d", time.Now().UnixNano())
	if !strings.HasPrefix(name, "ltqa-agent-docker-") {
		t.Fatal("refusing unsafe live Docker QA container name")
	}

	transport := newRecordingCollectorTransport(true)
	collector := NewDockerCollector(endpoint, transport, "ltqa-docker-host", 5*time.Second)
	if !collector.IsAvailable() {
		t.Fatalf("Docker endpoint %q is not available", endpoint)
	}

	var containerID string
	defer func() {
		if containerID == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := collector.client.removeContainer(ctx, containerID, true); err != nil && !strings.Contains(err.Error(), "404") {
			t.Errorf("cleanup exact QA container %s: %v", containerID, err)
		}
	}()

	create := protocol.DockerActionData{
		RequestID: "ltqa-create",
		Action:    "container.create",
		Params: map[string]string{
			"image":   image,
			"name":    name,
			"command": "/bin/sh\n-c\necho LTQA_DOCKER_RUNTIME_READY; exec sleep 600",
			"env":     "LTQA_SCOPE=disposable",
		},
	}
	result := runLiveDockerAction(t, collector, transport, create)
	if !result.Success || strings.TrimSpace(result.Data) == "" {
		t.Fatalf("create result = %+v", result)
	}
	containerID = strings.TrimSpace(result.Data)

	waitForLiveContainerState(t, collector, containerID, "running")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	published, err := collector.RefreshAndPublishFull(ctx, true)
	cancel()
	if err != nil || !published {
		t.Fatalf("full Docker discovery published=%t err=%v", published, err)
	}
	discovery := waitForLiveDockerDiscovery(t, transport)
	if discovery.Engine.Version == "" || discovery.Engine.APIVersion == "" {
		t.Fatalf("Docker engine discovery missing version data: %+v", discovery.Engine)
	}
	found := false
	for _, container := range discovery.Containers {
		if container.ID == containerID {
			found = true
			if container.State != "running" {
				t.Fatalf("discovered container state=%q, want running", container.State)
			}
		}
	}
	if !found {
		t.Fatalf("discovery omitted exact QA container %s", containerID)
	}
	if len(discovery.Images) == 0 || len(discovery.Networks) == 0 {
		t.Fatalf("full discovery incomplete: images=%d networks=%d volumes=%d", len(discovery.Images), len(discovery.Networks), len(discovery.Volumes))
	}

	logs := runLiveDockerAction(t, collector, transport, protocol.DockerActionData{
		RequestID:   "ltqa-logs",
		Action:      "container.logs",
		ContainerID: containerID,
		Params:      map[string]string{"tail": "20", "timestamps": "true"},
	})
	if !logs.Success || !strings.Contains(logs.Data, "LTQA_DOCKER_RUNTIME_READY") {
		t.Fatalf("container logs result = %+v", logs)
	}

	for _, action := range []struct {
		name      string
		wantState string
	}{
		{name: "container.pause", wantState: "paused"},
		{name: "container.unpause", wantState: "running"},
		{name: "container.restart", wantState: "running"},
		{name: "container.stop", wantState: "exited"},
		{name: "container.start", wantState: "running"},
	} {
		result := runLiveDockerAction(t, collector, transport, protocol.DockerActionData{
			RequestID:   "ltqa-" + strings.TrimPrefix(action.name, "container."),
			Action:      action.name,
			ContainerID: containerID,
			Params:      map[string]string{"timeout": "3"},
		})
		if !result.Success {
			t.Fatalf("%s failed: %+v", action.name, result)
		}
		waitForLiveContainerState(t, collector, containerID, action.wantState)
	}

	execTransport := newRecordingCollectorTransport(true)
	execManager := collector.NewExecManager()
	execPayload, err := json.Marshal(protocol.DockerExecStartData{
		SessionID:   "ltqa-exec",
		ContainerID: containerID,
		Command:     []string{"/bin/sh", "-c", "printf LTQA_EXEC_OK"},
		TTY:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	execManager.HandleExecStart(execTransport, protocol.Message{Type: protocol.MsgDockerExecStart, Data: execPayload})
	waitForLiveExecMarker(t, execTransport, "LTQA_EXEC_OK")
	execManager.CloseAll()

	remove := runLiveDockerAction(t, collector, transport, protocol.DockerActionData{
		RequestID:   "ltqa-remove",
		Action:      "container.remove",
		ContainerID: containerID,
		Params:      map[string]string{"force": "true"},
	})
	if !remove.Success {
		t.Fatalf("remove result = %+v", remove)
	}
	waitForLiveContainerAbsent(t, collector, containerID)
	containerID = ""
}

func runLiveDockerAction(t *testing.T, collector *DockerCollector, transport *recordingCollectorTransport, req protocol.DockerActionData) protocol.DockerActionResultData {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	collector.HandleDockerAction(transport, protocol.Message{Type: protocol.MsgDockerAction, ID: req.RequestID, Data: raw})
	deadline := time.After(35 * time.Second)
	for {
		select {
		case msg := <-transport.ch:
			if msg.Type != protocol.MsgDockerActionResult {
				continue
			}
			var result protocol.DockerActionResultData
			if err := json.Unmarshal(msg.Data, &result); err != nil {
				t.Fatal(err)
			}
			if result.RequestID == req.RequestID {
				return result
			}
		case <-deadline:
			t.Fatalf("timed out waiting for Docker action %s", req.Action)
		}
	}
}

func waitForLiveDockerDiscovery(t *testing.T, transport *recordingCollectorTransport) protocol.DockerDiscoveryData {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case msg := <-transport.ch:
			if msg.Type != protocol.MsgDockerDiscovery {
				continue
			}
			var discovery protocol.DockerDiscoveryData
			if err := json.Unmarshal(msg.Data, &discovery); err != nil {
				t.Fatal(err)
			}
			return discovery
		case <-deadline:
			t.Fatal("timed out waiting for Docker discovery")
		}
	}
}

func waitForLiveContainerState(t *testing.T, collector *DockerCollector, containerID, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		containers, err := collector.ListContainers(ctx)
		cancel()
		if err == nil {
			for _, container := range containers {
				if container.ID == containerID && container.State == want {
					return
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("container %s did not reach state %q", containerID, want)
}

func waitForLiveContainerAbsent(t *testing.T, collector *DockerCollector, containerID string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		containers, err := collector.ListContainers(ctx)
		cancel()
		found := false
		if err == nil {
			for _, container := range containers {
				found = found || container.ID == containerID
			}
			if !found {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("container %s still exists after exact cleanup", containerID)
}

func waitForLiveExecMarker(t *testing.T, transport *recordingCollectorTransport, marker string) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	var output strings.Builder
	for {
		select {
		case msg := <-transport.ch:
			switch msg.Type {
			case protocol.MsgDockerExecData:
				var stream protocol.DockerExecDataPayload
				if err := json.Unmarshal(msg.Data, &stream); err != nil {
					t.Fatal(err)
				}
				decoded, err := base64.StdEncoding.DecodeString(stream.Data)
				if err != nil {
					t.Fatalf("decode exec output: %v", err)
				}
				output.Write(decoded)
				if strings.Contains(output.String(), marker) {
					return
				}
			case protocol.MsgDockerExecClosed:
				if !strings.Contains(output.String(), marker) {
					t.Fatalf("exec closed before marker; output=%q", output.String())
				}
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for Docker exec marker; output=%q", output.String())
		}
	}
}
