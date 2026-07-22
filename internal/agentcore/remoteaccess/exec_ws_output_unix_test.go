//go:build !windows

package remoteaccess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

const outputTruncatedMarker = "\n...output truncated"

func TestHandleCommandRequestCapsOutputWhileProcessContinues(t *testing.T) {
	transport := newMockTransport()
	req := protocol.CommandRequestData{
		JobID:     "command-output-cap",
		SessionID: "session-1",
		CommandID: "command-1",
		Command:   "head -c 131072 /dev/zero",
		Timeout:   5,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal command request: %v", err)
	}

	HandleCommandRequest(transport, protocol.Message{Type: protocol.MsgCommandRequest, Data: data}, ExecConfig{APIToken: "opaque-token"})

	msg := readExecTestMessage(t, transport.messages)
	if msg.Type != protocol.MsgCommandResult {
		t.Fatalf("message type = %q, want %q", msg.Type, protocol.MsgCommandResult)
	}
	var result protocol.CommandResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("decode command result: %v", err)
	}
	assertCappedSuccessfulOutput(t, result.Status, result.Output, "")
}

func TestHandleUpdateRequestCapsOutputWhileProcessContinues(t *testing.T) {
	binDir := t.TempDir()
	aptGetPath := filepath.Join(binDir, "apt-get")
	if err := os.WriteFile(aptGetPath, []byte("#!/bin/sh\n/usr/bin/head -c 131072 /dev/zero\n"), 0o700); err != nil {
		t.Fatalf("write fake apt-get: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	transport := newMockTransport()
	req := protocol.UpdateRequestData{JobID: "update-output-cap", Mode: "os_packages"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal update request: %v", err)
	}

	HandleUpdateRequest(transport, protocol.Message{Type: protocol.MsgUpdateRequest, Data: data}, ExecConfig{APIToken: "opaque-token"})

	for {
		msg := readExecTestMessage(t, transport.messages)
		if msg.Type != protocol.MsgUpdateResult {
			continue
		}
		var result protocol.UpdateResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode update result: %v", err)
		}
		assertCappedSuccessfulOutput(t, result.Status, result.Output, result.Error)
		return
	}
}

func readExecTestMessage(t *testing.T, messages <-chan protocol.Message) protocol.Message {
	t.Helper()
	select {
	case msg := <-messages:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command/update result")
		return protocol.Message{}
	}
}

func assertCappedSuccessfulOutput(t *testing.T, status, output, errMsg string) {
	t.Helper()
	if status != "succeeded" {
		t.Fatalf("status = %q, want succeeded (error %q)", status, errMsg)
	}
	if errMsg != "" {
		t.Fatalf("error = %q, want empty", errMsg)
	}
	if !strings.HasSuffix(output, outputTruncatedMarker) {
		t.Fatalf("output does not end with truncation marker (length %d)", len(output))
	}
	if got, want := len(output), MaxCommandOutputBytes+len(outputTruncatedMarker); got != want {
		t.Fatalf("output length = %d, want %d", got, want)
	}
}
