package remoteaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type commandOutputOwnerTransport struct {
	*mockTransport
	ctx context.Context
}

func (s commandOutputOwnerTransport) Context() context.Context { return s.ctx }

// This executes the real request handler and an actual child/descendant pair.
// Releasing the descendant is an explicit fixture protocol; cancellation may
// stop only the command's own process group, never unrelated processes.
func TestHandleCommandRequestBoundsInheritedOutputDrain(t *testing.T) {
	for _, mode := range []string{"exited-parent", "canceled-owner"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			quoted := strconv.Quote(executable)
			t.Setenv("LABTETHER_EXEC_ALLOWED_BINARIES", filepath.Base(executable))
			t.Setenv("LABTETHER_SHELL_COMMAND_ALLOWLIST_PREFIXES", quoted)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := commandOutputOwnerTransport{newMockTransport(), ctx}
			request := protocol.CommandRequestData{JobID: "drain-job", SessionID: "drain-session", CommandID: "drain-command", Timeout: 10,
				Command: quoted + " -test.run=^TestRemoteCommandOutputHelper$ -- " + mode + " " + strconv.Quote(dir)}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
					t.Error(err)
				}
				if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
					if mode == "canceled-owner" && remoteCommandKillsProcessGroup {
						// Cancellation stopped the command's process group, so the
						// descendant must not survive to observe the release marker.
						if waitRemoteCommandFixtureFile(filepath.Join(dir, "closed"), 500*time.Millisecond) {
							t.Error("canceled command left its descendant running")
						}
					} else if !waitRemoteCommandFixtureFile(filepath.Join(dir, "closed"), 3*time.Second) {
						t.Error("owned fixture descendant did not release its output")
					}
				}
				select {
				case <-finished:
				case <-time.After(3 * time.Second):
					t.Error("request handler did not stop after fixture release")
				}
			})
			go func() {
				defer close(finished)
				HandleCommandRequest(transport, protocol.Message{Type: protocol.MsgCommandRequest, Data: raw}, ExecConfig{APIToken: "opaque-test-token"})
			}()
			if !waitRemoteCommandFixtureFile(filepath.Join(dir, "ready"), 3*time.Second) {
				t.Fatal("fixture did not start")
			}
			if mode == "canceled-owner" {
				cancel()
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("inherited output kept request handler occupied")
			}
			var result protocol.CommandResultData
			select {
			case message := <-transport.messages:
				if message.Type != protocol.MsgCommandResult {
					t.Fatalf("unexpected result type: %s", message.Type)
				}
				if err := json.Unmarshal(message.Data, &result); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("missing command result")
			}
			if result.Status != "failed" || result.JobID != request.JobID || result.CommandID != request.CommandID || result.SessionID != request.SessionID {
				t.Fatalf("wrong failed result: %+v", result)
			}
			if !strings.Contains(result.Output, "held-output-ready") {
				t.Fatalf("lost retained output: %q", result.Output)
			}
			if mode == "exited-parent" && !strings.Contains(result.Output, "descendant processes may still be running") {
				t.Fatalf("missing drain uncertainty: %q", result.Output)
			}
			if len(transport.messages) != 0 {
				t.Fatal("request emitted duplicate final results")
			}
		})
	}
}

func TestRemoteCommandCaptureRetainsOnlyBoundedOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRemoteCommandOutputHelper$", "--", "flood", t.TempDir())
	output, err := runRemoteCommandOutput(cmd)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "\n...output truncated"
	if len(output) != MaxCommandOutputBytes+len(marker) || !strings.HasSuffix(output, marker) {
		t.Fatalf("unbounded or unmarked capture: %d bytes", len(output))
	}
}

func TestRemoteCommandOutputHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 || len(os.Args) != index+3 {
		return
	}
	mode, dir := os.Args[index+1], os.Args[index+2]
	if mode == "flood" {
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", MaxCommandOutputBytes*3)))
		return
	}
	if mode == "held-output" {
		fmt.Fprintln(os.Stdout, "held-output-ready")
		if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		waitRemoteCommandFixtureFile(filepath.Join(dir, "release"), 8*time.Second)
		_ = os.Stdout.Close()
		_ = os.Stderr.Close()
		if err := os.WriteFile(filepath.Join(dir, "closed"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if mode != "exited-parent" && mode != "canceled-owner" {
		t.Fatalf("unknown fixture mode %q", mode)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRemoteCommandOutputHelper$", "--", "held-output", dir)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Release(); err != nil {
		t.Fatal(err)
	}
	if !waitRemoteCommandFixtureFile(filepath.Join(dir, "ready"), 3*time.Second) {
		t.Fatal("descendant did not start")
	}
	if mode == "canceled-owner" {
		waitRemoteCommandFixtureFile(filepath.Join(dir, "release"), 8*time.Second)
	}
}

func waitRemoteCommandFixtureFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
