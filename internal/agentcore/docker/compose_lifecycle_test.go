package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type composeContextTransport struct {
	*recordingCollectorTransport
	ctx context.Context
}

func (sender composeContextTransport) Context() context.Context { return sender.ctx }

func TestHandleComposeActionCancellation(t *testing.T) {
	for _, phase := range []string{"before-deploy", "lookup", "child"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sender := composeContextTransport{newRecordingCollectorTransport(true), ctx}
			selected := composeTestSelection(t)
			lookupStarted := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "lookup" {
					lookupStarted <- struct{}{}
					<-r.Context().Done()
					return
				}
				_ = json.NewEncoder(w).Encode(composeRows(selected))
			}))
			defer server.Close()
			t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true")
			t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
			dc := NewDockerCollector(server.URL, sender, "host", time.Minute)
			startedPath := filepath.Join(t.TempDir(), "child-started")
			var child *exec.Cmd
			detects := 0
			oldDetect, oldCommand := dockerComposeCLIDetect, dockerComposeNewCommandContext
			defer func() { dockerComposeCLIDetect, dockerComposeNewCommandContext = oldDetect, oldCommand }()
			dockerComposeCLIDetect = func() (int, bool) { detects++; return 2, true }
			dockerComposeNewCommandContext = func(ctx context.Context, _ string, _ ...string) (*exec.Cmd, error) {
				child = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestComposeSelectionChild$", "--", "compose-wait-child", startedPath)
				return child, nil
			}
			req := protocol.DockerComposeActionData{RequestID: phase, StackName: selected.Name, ConfigDir: selected.Dir, ConfigFiles: selected.Files, EndpointID: dc.composeEndpointID(), Action: "restart"}
			if phase == "before-deploy" {
				req.Action = "deploy"
				req.ConfigDir = filepath.Join(t.TempDir(), "absent")
				req.ConfigFiles = nil
				req.ComposeYAML = "services: {}\n"
				cancel()
			}
			data, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				dc.HandleComposeAction(sender, protocol.Message{Type: protocol.MsgDockerComposeActionV2, Data: data})
			}()
			// The request owns its child. Cancel and join on every assertion-failure path.
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("compose owner did not finish during cleanup")
				}
			}()
			switch phase {
			case "lookup":
				select {
				case <-lookupStarted:
				case <-done:
					t.Fatal("handler returned before lookup")
				case <-time.After(3 * time.Second):
					t.Fatal("lookup did not start")
				}
			case "child":
				waitUntil(t, 3*time.Second, func() bool { _, err := os.Stat(startedPath); return err == nil }, "owned compose child start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("canceled compose owner remained blocked")
			}
			message := waitForCollectorMessage(t, sender.recordingCollectorTransport, time.Second)
			var result protocol.DockerComposeResultData
			if json.Unmarshal(message.Data, &result) != nil || result.Success || result.Error == "" {
				t.Fatalf("cancellation lost: %+v", result)
			}
			if phase == "child" {
				if child == nil || child.ProcessState == nil {
					t.Fatal("owned child was not waited")
				}
			} else if child != nil {
				t.Fatal("child started after cancellation")
			}
			if phase == "before-deploy" {
				if detects != 0 {
					t.Fatal("canceled deploy ran CLI detection")
				}
				if _, err := os.Stat(req.ConfigDir); !os.IsNotExist(err) {
					t.Fatal("canceled deploy wrote files")
				}
			}
		})
	}
}

func TestHandleComposeActionDrainsAndBoundsCommandOutput(t *testing.T) {
	oldDetect := dockerComposeCLIDetect
	oldNewCommandContext := dockerComposeNewCommandContext
	t.Cleanup(func() {
		dockerComposeCLIDetect = oldDetect
		dockerComposeNewCommandContext = oldNewCommandContext
	})

	dockerComposeCLIDetect = func() (int, bool) { return 2, true }
	dockerComposeNewCommandContext = func(ctx context.Context, _ string, _ ...string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestComposeSelectionChild$", "--", "compose-output-child"), nil
	}

	transport := newRecordingCollectorTransport(true)
	dc := NewDockerCollector("/tmp/docker.sock", transport, "asset-1", 30*time.Second)
	dc.client = NewDockerClient("http://localhost:1")

	raw, err := json.Marshal(protocol.DockerComposeActionData{
		RequestID:   "compose-bounded-output",
		StackName:   "bounded-output",
		ComposeYAML: "services: {}\n",
		Action:      "deploy",
		ConfigDir:   filepath.Join(useComposeStacksRoot(t), "bounded-output"),
	})
	if err != nil {
		t.Fatalf("marshal docker compose action: %v", err)
	}
	dc.HandleComposeAction(transport, protocol.Message{Type: protocol.MsgDockerComposeAction, Data: raw})

	msg := waitForCollectorMessage(t, transport, time.Second)
	var result protocol.DockerComposeResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("decode docker compose result: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful compose command, got error %q", result.Error)
	}
	if len(result.Output) > composeActionOutputLimit+len("\n...output truncated") {
		t.Fatalf("compose output length = %d, expected bounded output", len(result.Output))
	}
	if !strings.HasSuffix(result.Output, "...output truncated") {
		t.Fatalf("compose output did not report truncation")
	}
}
