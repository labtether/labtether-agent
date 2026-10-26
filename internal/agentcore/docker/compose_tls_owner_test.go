package docker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestComposeHTTPSVerifiedTrustAndCommandOwner(t *testing.T) {
	for _, action := range []string{"restart", "deploy", "legacy", "mixed-scheme"} {
		t.Run(action, func(t *testing.T) {
			t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
			selected := composeTestSelection(t)
			var pings atomic.Int32
			server, root := composeTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/engine/_ping":
					pings.Add(1)
					_, _ = w.Write([]byte("OK"))
				case "/engine/containers/json":
					_ = json.NewEncoder(w).Encode(composeRows(selected))
				default:
					http.NotFound(w, r)
				}
			}))
			sender := newRecordingCollectorTransport(true)
			endpoint := server.URL + "/engine"
			if action == "mixed-scheme" {
				endpoint = strings.Replace(endpoint, "https://", "hTtPs://", 1)
			}
			dc := NewDockerCollector(endpoint, sender, "host", time.Minute)
			dc.client.httpClient = composeTrustedClient(root)
			output := filepath.Join(t.TempDir(), "child.json")
			child := composeTLSChildHook(t, output, "success")
			for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTPS_PROXY"} {
				t.Setenv(key, "hostile-ambient-setting")
			}
			// Keep the user's existing registry auth path; daemon flags must win.
			home := os.Getenv("HOME")
			req := protocol.DockerComposeActionData{RequestID: action, StackName: selected.Name, ConfigDir: selected.Dir, ConfigFiles: selected.Files, EndpointID: dc.composeEndpointID(), Action: action}
			if action == "mixed-scheme" {
				req.Action = "restart"
			}
			if action == "deploy" {
				req.ConfigDir = filepath.Join(t.TempDir(), "new-stack")
				req.ConfigFiles = nil
				req.ComposeYAML = "services: {}\n"
			}
			kind := protocol.MsgDockerComposeActionV2
			if action == "legacy" {
				kind = protocol.MsgDockerComposeAction
				req.Action, req.EndpointID, req.ConfigFiles = "restart", "", nil
			}
			result := composeRequest(t, dc, sender, req, kind)
			if !result.Success || result.Output != "verified compose ok" || *child == nil || (*child).ProcessState == nil || pings.Load() != 2 {
				t.Fatalf("TLS command owner failed: %+v pings=%d", result, pings.Load())
			}
			record := readComposeTLSChild(t, output)
			if !bytes.Equal(record.Root, root) || record.Env["HOME"] != home || record.Env["DOCKER_HOST"] != "tcp://"+strings.TrimPrefix(server.URL, "https://")+"/engine" {
				t.Fatal("wrong trust root, daemon or existing registry home")
			}
			for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTPS_PROXY"} {
				if record.Env[key] != "" {
					t.Fatalf("ambient daemon setting reached child: %s", key)
				}
			}
			if runtime.GOOS != "windows" && (record.FileMode != 0o600 || record.DirMode != 0o700) {
				t.Fatal("trust file/directory permissions are not private")
			}
			assertComposeTrustRemoved(t, record.CA)
			if action == "deploy" {
				data, err := os.ReadFile(filepath.Join(req.ConfigDir, "docker-compose.yml"))
				if err != nil || string(data) != req.ComposeYAML {
					t.Fatal("verified deploy did not write exact YAML", err)
				}
			}
		})
	}
}

func TestComposeHTTPSRejectsBeforeEffects(t *testing.T) {
	for _, mode := range []string{"untrusted", "hostname", "redirect", "lookup-redirect", "unverified", "large-body", "selection-error", "v1-cli"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
			var requests atomic.Int32
			server, root := composeTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if mode == "redirect" || (mode == "lookup-redirect" && r.URL.Path == "/containers/json") {
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				if mode == "large-body" {
					_, _ = w.Write([]byte(strings.Repeat("x", 4097)))
					return
				}
				_, _ = w.Write([]byte("OK"))
			}))
			endpoint := server.URL
			if mode == "hostname" {
				endpoint = strings.Replace(endpoint, "127.0.0.1", "localhost", 1)
			}
			sender := newRecordingCollectorTransport(true)
			dc := NewDockerCollector(endpoint, sender, "host", time.Minute)
			if mode != "untrusted" {
				dc.client.httpClient = composeTrustedClient(root)
			}
			if mode == "unverified" {
				// Deliberately unsafe injected client: the production bridge must
				// reject missing VerifiedChains even after a successful handshake.
				dc.client.httpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- negative fixture only.
			}
			oldDetect, oldCommand := dockerComposeCLIDetect, dockerComposeNewCommandContext
			t.Cleanup(func() { dockerComposeCLIDetect, dockerComposeNewCommandContext = oldDetect, oldCommand })
			dockerComposeCLIDetect = func() (int, bool) {
				if mode == "v1-cli" {
					return 1, true
				}
				return 2, true
			}
			launches := 0
			dockerComposeNewCommandContext = func(context.Context, string, ...string) (*exec.Cmd, error) { launches++; return nil, nil }
			trustTemp := t.TempDir()
			for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(key, trustTemp)
			}
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			req := protocol.DockerComposeActionData{RequestID: mode, StackName: "project", Action: "deploy", ConfigDir: dir, ComposeYAML: "services: {}\n", EndpointID: dc.composeEndpointID()}
			if mode == "lookup-redirect" {
				req.Action = "restart"
			}
			if mode == "selection-error" {
				req.ConfigFiles = []string{filepath.Join(dir, "not-the-deploy-file.yml")}
			}
			result := composeRequest(t, dc, sender, req, protocol.MsgDockerComposeActionV2)
			if result.Success || result.Error == "" || launches != 0 {
				t.Fatalf("unverified deploy reached command: %+v launches=%d", result, launches)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("unverified deploy wrote files")
			}
			leftovers, err := filepath.Glob(filepath.Join(trustTemp, "labtether-compose-ca-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatal("failed action retained TLS trust material", err)
			}
			if mode == "redirect" && requests.Load() != 1 {
				t.Fatal("TLS probe followed a redirect")
			}
			if mode == "lookup-redirect" && requests.Load() != 2 {
				t.Fatal("HTTPS selection followed a redirect")
			}
			if mode == "v1-cli" && (requests.Load() != 0 || result.Error != composeHTTPSUnsupported) {
				t.Fatal("unsupported CLI/wire did not fail before TLS probe")
			}
		})
	}
}

func TestComposeHTTPSCancellationCleanup(t *testing.T) {
	for _, phase := range []string{"probe", "child"} {
		t.Run(phase, func(t *testing.T) {
			t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
			started := make(chan struct{}, 1)
			server, root := composeTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "probe" {
					started <- struct{}{}
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte("OK"))
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sender := composeContextTransport{newRecordingCollectorTransport(true), ctx}
			dc := NewDockerCollector(server.URL, sender, "host", time.Minute)
			dc.client.httpClient = composeTrustedClient(root)
			output := filepath.Join(t.TempDir(), "started.json")
			child := composeTLSChildHook(t, output, "wait")
			dir := filepath.Join(t.TempDir(), "new-stack")
			data, err := json.Marshal(protocol.DockerComposeActionData{RequestID: phase, StackName: "project", Action: "deploy", ConfigDir: dir, ComposeYAML: "services: {}\n", EndpointID: dc.composeEndpointID()})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				dc.HandleComposeAction(sender, protocol.Message{Type: protocol.MsgDockerComposeActionV2, Data: data})
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("TLS action owner did not finish cleanup")
				}
			}()
			if phase == "probe" {
				select {
				case <-started:
				case <-done:
					t.Fatal("TLS probe ended before cancellation")
				case <-time.After(3 * time.Second):
					t.Fatal("TLS probe did not start")
				}
			} else {
				waitUntil(t, 3*time.Second, func() bool {
					data, err := os.ReadFile(output)
					return err == nil && json.Valid(data)
				}, "TLS child start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("TLS cancellation did not finish")
			}
			message := waitForCollectorMessage(t, sender.recordingCollectorTransport, time.Second)
			var result protocol.DockerComposeResultData
			if json.Unmarshal(message.Data, &result) != nil || result.Success || result.Error == "" {
				t.Fatalf("TLS cancellation lost: %+v", result)
			}
			if phase == "child" {
				if *child == nil || (*child).ProcessState == nil {
					t.Fatal("TLS child was not waited before trust cleanup")
				}
				assertComposeTrustRemoved(t, readComposeTLSChild(t, output).CA)
			} else {
				if *child != nil {
					t.Fatal("TLS probe cancellation launched command")
				}
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatal("TLS probe cancellation wrote deploy")
				}
			}
		})
	}
}
