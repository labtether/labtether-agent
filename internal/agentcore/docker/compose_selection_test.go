package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type composeChildRecord struct {
	Args []string
	Dir  string
	Env  map[string]string
}

// sameChildDir compares the working directory the child read back from the OS
// with the directory the agent passed. macOS reports t.TempDir()'s
// /var/folders path as /private/var/folders, so compare the resolved paths.
func sameChildDir(t *testing.T, got, want string) bool {
	t.Helper()
	gotReal, gotErr := filepath.EvalSymlinks(got)
	wantReal, wantErr := filepath.EvalSymlinks(want)
	return gotErr == nil && wantErr == nil && gotReal == wantReal
}

// Re-exec is a real bounded child and records the final exec.Cmd argv/env/Dir.
// It performs one HTTP read against the selected synthetic Engine, not Docker.
func TestComposeSelectionChild(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "compose-selection-child" || arg == "compose-output-child" || arg == "compose-wait-child" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	if os.Args[marker] == "compose-output-child" {
		_, _ = os.Stdout.WriteString(strings.Repeat("x", 262144))
		os.Exit(0)
	}
	if os.Args[marker] == "compose-wait-child" {
		if os.WriteFile(os.Args[marker+1], []byte("started"), 0o600) != nil {
			os.Exit(6)
		}
		time.Sleep(time.Minute)
		os.Exit(7)
	}
	output, args := os.Args[marker+1], os.Args[marker+2:]
	cwd, err := os.Getwd()
	if err != nil {
		os.Exit(2)
	}
	record := composeChildRecord{Args: args, Dir: cwd, Env: make(map[string]string)}
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "COMPOSE_PROJECT_NAME", "LABTETHER_COMPOSE_TEST_PRIVATE"} {
		record.Env[key] = os.Getenv(key)
	}
	if len(args) > 2 && args[1] == "--host" && strings.HasPrefix(args[2], "tcp://") {
		client := &http.Client{Timeout: time.Second}
		response, err := client.Get("http://" + strings.TrimPrefix(args[2], "tcp://") + "/_ping")
		if err != nil {
			os.Exit(3)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			os.Exit(4)
		}
	}
	data, _ := json.Marshal(record)
	if os.WriteFile(output, data, 0o600) != nil {
		os.Exit(5)
	}
	_, _ = os.Stdout.WriteString("compose ok")
	os.Exit(0)
}

func composeTestSelection(t *testing.T) composeSelection {
	t.Helper()
	dir := t.TempDir()
	files := []string{filepath.Join(t.TempDir(), "base.yml"), filepath.Join(dir, " override config.yml")}
	for _, file := range files {
		if err := os.WriteFile(file, []byte("services: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return composeSelection{Name: "not_the_directory", Dir: dir, Files: files}
}

func composeRows(selected composeSelection) []DockerContainer {
	return []DockerContainer{
		{ID: "one", Names: []string{"/one"}, State: "running", Labels: map[string]string{composeProjectLabel: selected.Name, composeDirectoryLabel: selected.Dir, composeFilesLabel: strings.Join(selected.Files, ",")}},
		{ID: "two", Names: []string{"/two"}, State: "exited", Labels: map[string]string{composeProjectLabel: selected.Name, composeDirectoryLabel: selected.Dir, composeFilesLabel: strings.Join(selected.Files, ",")}},
	}
}

func composeFixture(t *testing.T, selected composeSelection, rows []DockerContainer) (*DockerCollector, *recordingCollectorTransport, *atomic.Int32) {
	t.Helper()
	t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	pings := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/engine/containers/json":
			var filter map[string][]string
			if r.URL.Query().Get("all") != "1" || json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filter) != nil || !reflect.DeepEqual(filter["label"], []string{composeProjectLabel + "=" + selected.Name}) {
				http.Error(w, "wrong selection query", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(rows)
		case "/engine/_ping":
			pings.Add(1)
			_, _ = w.Write([]byte("OK"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	sender := newRecordingCollectorTransport(true)
	return NewDockerCollector(srv.URL+"/engine", sender, "host", time.Minute), sender, pings
}

func composeRequest(t *testing.T, dc *DockerCollector, sender *recordingCollectorTransport, req protocol.DockerComposeActionData, kind string) protocol.DockerComposeResultData {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	dc.HandleComposeAction(sender, protocol.Message{Type: kind, Data: data})
	message := waitForCollectorMessage(t, sender, time.Second)
	var result protocol.DockerComposeResultData
	if message.Type != protocol.MsgDockerComposeResult || json.Unmarshal(message.Data, &result) != nil {
		t.Fatalf("unexpected result %#v", message)
	}
	return result
}

func composeChildHook(t *testing.T, version int, output string, launches *int) {
	t.Helper()
	oldDetect, oldCommand := dockerComposeCLIDetect, dockerComposeNewCommandContext
	t.Cleanup(func() { dockerComposeCLIDetect, dockerComposeNewCommandContext = oldDetect, oldCommand })
	dockerComposeCLIDetect = func() (int, bool) { return version, true }
	dockerComposeNewCommandContext = func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
		*launches++
		childArgs := []string{"-test.run=^TestComposeSelectionChild$", "--", "compose-selection-child", output, name}
		return exec.CommandContext(ctx, os.Args[0], append(childArgs, args...)...), nil
	}
}

func TestHandleComposeActionExactSelection(t *testing.T) {
	for _, mode := range []struct {
		name string
		wire string
		cli  int
	}{{"v2-cli", protocol.MsgDockerComposeActionV2, 2}, {"v1-cli", protocol.MsgDockerComposeActionV2, 1}, {"legacy-safe-lookup", protocol.MsgDockerComposeAction, 2}} {
		t.Run(mode.name, func(t *testing.T) {
			selected := composeTestSelection(t)
			dc, sender, pings := composeFixture(t, selected, composeRows(selected))
			output := filepath.Join(t.TempDir(), "child.json")
			launches := 0
			composeChildHook(t, mode.cli, output, &launches)
			for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
				t.Setenv(key, "wrong-ambient-value")
			}
			// A project .env is present; this fixture proves the final explicit env/flags.
			// Parsing that file with a real Docker CLI remains a separate live gate.
			t.Setenv("LABTETHER_COMPOSE_TEST_PRIVATE", "must-not-reach-child")
			if err := os.WriteFile(filepath.Join(selected.Dir, ".env"), []byte("DOCKER_HOST=tcp://127.0.0.1:1\nCOMPOSE_PROJECT_NAME=wrong\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			req := protocol.DockerComposeActionData{RequestID: "selected", StackName: selected.Name, ConfigDir: selected.Dir, ConfigFiles: selected.Files, EndpointID: dc.composeEndpointID(), Action: "restart"}
			if mode.wire == protocol.MsgDockerComposeAction {
				req.ConfigFiles = nil
				req.EndpointID = ""
			}
			result := composeRequest(t, dc, sender, req, mode.wire)
			if !result.Success || launches != 1 || pings.Load() != 1 {
				t.Fatalf("result=%+v launches=%d pings=%d", result, launches, pings.Load())
			}
			var got composeChildRecord
			data, err := os.ReadFile(output)
			if err != nil || json.Unmarshal(data, &got) != nil {
				t.Fatal("missing child record", err)
			}
			host, err := composeDaemonHost(dc.socketPath)
			if err != nil {
				t.Fatal(err)
			}
			name, args := composeCommandArgs(mode.cli, host, selected, "restart")
			if !reflect.DeepEqual(got.Args, append([]string{name}, args...)) || !sameChildDir(t, got.Dir, selected.Dir) || got.Env["DOCKER_HOST"] != host || got.Env["COMPOSE_PROJECT_NAME"] != selected.Name {
				t.Fatalf("selection changed: %+v", got)
			}
			for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
				if got.Env[key] != "" {
					t.Fatalf("override leaked %s", key)
				}
			}
			if got.Env["LABTETHER_COMPOSE_TEST_PRIVATE"] != "" {
				t.Fatal("strict child allowlist broadened")
			}
			if got.Env["NO_PROXY"] != "*" || os.Getenv("DOCKER_CONTEXT") != "wrong-ambient-value" {
				t.Fatal("proxy or parent env changed")
			}
		})
	}
}

func TestHandleComposeActionRejectsChangedSelection(t *testing.T) {
	for _, test := range []string{"order", "stopped-conflict", "missing-label", "different-project", "overflow", "directory", "missing-file", "endpoint", "missing-endpoint", "invalid-project"} {
		t.Run(test, func(t *testing.T) {
			selected := composeTestSelection(t)
			rows := composeRows(selected)
			switch test {
			case "stopped-conflict":
				rows[1].Labels[composeFilesLabel] = selected.Files[1] + "," + selected.Files[0]
			case "missing-label":
				delete(rows[1].Labels, composeFilesLabel)
			case "different-project":
				rows[1].Labels[composeProjectLabel] = "other"
			case "overflow":
				for len(rows) <= maxContainersPerHost {
					rows = append(rows, rows[0])
				}
			case "missing-file":
				if err := os.Remove(selected.Files[0]); err != nil {
					t.Fatal(err)
				}
			}
			dc, sender, pings := composeFixture(t, selected, rows)
			launches := 0
			composeChildHook(t, 2, filepath.Join(t.TempDir(), "child.json"), &launches)
			req := protocol.DockerComposeActionData{RequestID: test, StackName: selected.Name, ConfigDir: selected.Dir, ConfigFiles: append([]string(nil), selected.Files...), EndpointID: dc.composeEndpointID(), Action: "down"}
			switch test {
			case "order":
				req.ConfigFiles[0], req.ConfigFiles[1] = req.ConfigFiles[1], req.ConfigFiles[0]
			case "directory":
				req.ConfigDir = t.TempDir()
			case "endpoint":
				req.EndpointID = strings.Repeat("a", 64)
			case "missing-endpoint":
				req.EndpointID = ""
			case "invalid-project":
				req.StackName = "My Project"
			}
			result := composeRequest(t, dc, sender, req, protocol.MsgDockerComposeActionV2)
			if result.Success || result.Error == "" || launches != 0 || pings.Load() != 0 {
				t.Fatalf("unsafe dispatch: %+v launches%d", result, launches)
			}
		})
	}
}

func TestComposeDeployRejectsBeforeWriting(t *testing.T) {
	for _, test := range []string{"endpoint-query", "stale-endpoint", "invalid-project"} {
		t.Run(test, func(t *testing.T) {
			sender := newRecordingCollectorTransport(true)
			endpoint := "/tmp/docker.sock"
			if test == "endpoint-query" {
				endpoint = "https://docker.example:2376?unsupported=1"
			}
			dc := NewDockerCollector(endpoint, sender, "host", time.Minute)
			detects := 0
			old := dockerComposeCLIDetect
			t.Cleanup(func() { dockerComposeCLIDetect = old })
			dockerComposeCLIDetect = func() (int, bool) { detects++; return 2, true }
			dir := filepath.Join(t.TempDir(), "not-created")
			req := protocol.DockerComposeActionData{RequestID: test, StackName: "project", Action: "deploy", ConfigDir: dir, ComposeYAML: "services: {}\n", EndpointID: dc.composeEndpointID()}
			if test == "stale-endpoint" {
				req.EndpointID = strings.Repeat("b", 64)
			}
			if test == "invalid-project" {
				req.StackName = "Project Wrong"
			}
			result := composeRequest(t, dc, sender, req, protocol.MsgDockerComposeActionV2)
			if result.Success || detects != 0 {
				t.Fatalf("pre-effect failure missing: %+v detects%d", result, detects)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("deploy created a path before rejection")
			}
			if test == "endpoint-query" && result.Error != "Docker endpoint cannot be represented by Compose" {
				t.Fatalf("unexpected TLS capability error %q", result.Error)
			}
		})
	}
}
