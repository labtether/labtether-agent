package agentcore

import (
	"encoding/base64"
	"encoding/json"
	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTerminalManagerProbeReportsTmuxAvailability(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	tm := newTerminalManager()
	tm.HandleTerminalProbe(transport)

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgTerminalProbed, 2*time.Second)
	var probe protocol.TerminalProbeResponse
	if err := json.Unmarshal(msg.Data, &probe); err != nil {
		t.Fatalf("decode terminal probe payload: %v", err)
	}

	tmuxPath, err := exec.LookPath("tmux")
	wantHasTmux := err == nil && tmuxPath != ""
	if probe.HasTmux != wantHasTmux {
		t.Fatalf("expected has_tmux=%v, got %v", wantHasTmux, probe.HasTmux)
	}
	if wantHasTmux && probe.TmuxPath != tmuxPath {
		t.Fatalf("expected tmux path %q, got %q", tmuxPath, probe.TmuxPath)
	}
}

func TestTerminalManagerTmuxKillEndsSavedSession(t *testing.T) {
	tmuxPath, err := exec.LookPath("tmux")
	if err != nil || strings.TrimSpace(tmuxPath) == "" {
		t.Skip("tmux not available")
	}

	sessionName := "labtether-test-kill-" + strings.ReplaceAll(t.Name(), "/", "-")
	createCmd := exec.Command(tmuxPath, "new-session", "-d", "-s", sessionName)
	if output, err := createCmd.CombinedOutput(); err != nil {
		t.Fatalf("create tmux session: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	defer func() {
		_ = exec.Command(tmuxPath, "kill-session", "-t", sessionName).Run()
	}()

	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	tm := newTerminalManager()
	raw, err := json.Marshal(protocol.TerminalTmuxKillData{
		JobID:       "job-kill",
		SessionID:   "sess-kill",
		CommandID:   "persistent.tmux.kill",
		TmuxSession: sessionName,
		Timeout:     5,
	})
	if err != nil {
		t.Fatalf("marshal terminal tmux kill request: %v", err)
	}

	tm.HandleTerminalTmuxKill(transport, protocol.Message{Data: raw})

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgCommandResult, 5*time.Second)
	var result protocol.CommandResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("decode tmux kill result: %v", err)
	}
	if result.Status != "succeeded" {
		t.Fatalf("expected succeeded tmux kill result, got %+v", result)
	}

	checkCmd := exec.Command(tmuxPath, "has-session", "-t", sessionName)
	if err := checkCmd.Run(); err == nil {
		t.Fatalf("expected tmux session %q to be gone after kill", sessionName)
	}
}

func TestTerminalManagerStartStreamsOutputAndCleansUp(t *testing.T) {
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	tm := newTerminalManager()
	defer tm.CloseAll()

	startRaw, err := json.Marshal(protocol.TerminalStartData{
		SessionID: "sess-1",
		Shell:     shellPath,
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("marshal terminal start: %v", err)
	}

	tm.HandleTerminalStart(transport, protocol.Message{Data: startRaw})

	startedMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgTerminalStarted, 5*time.Second)
	var started protocol.TerminalStartedData
	if err := json.Unmarshal(startedMsg.Data, &started); err != nil {
		t.Fatalf("decode terminal started payload: %v", err)
	}
	if started.SessionID != "sess-1" {
		t.Fatalf("expected session_id sess-1, got %q", started.SessionID)
	}

	inputRaw, err := json.Marshal(protocol.TerminalDataPayload{
		SessionID: "sess-1",
		Data:      base64.StdEncoding.EncodeToString([]byte("printf 'terminal-ok\\n'; exit\n")),
	})
	if err != nil {
		t.Fatalf("marshal terminal input: %v", err)
	}
	tm.HandleTerminalData(protocol.Message{Data: inputRaw})

	var output strings.Builder
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg, ok := <-messages:
			if !ok {
				t.Fatal("transport closed before terminal session finished")
			}
			switch msg.Type {
			case protocol.MsgTerminalData:
				var payload protocol.TerminalDataPayload
				if err := json.Unmarshal(msg.Data, &payload); err != nil {
					t.Fatalf("decode terminal data payload: %v", err)
				}
				decoded, err := base64.StdEncoding.DecodeString(payload.Data)
				if err != nil {
					t.Fatalf("decode terminal data chunk: %v", err)
				}
				output.Write(decoded)
			case protocol.MsgTerminalClosed:
				var closed protocol.TerminalCloseData
				if err := json.Unmarshal(msg.Data, &closed); err != nil {
					t.Fatalf("decode terminal closed payload: %v", err)
				}
				if closed.SessionID != "sess-1" {
					t.Fatalf("expected closed session_id sess-1, got %q", closed.SessionID)
				}
				if !strings.Contains(closed.Reason, "shell exited") {
					t.Fatalf("expected shell-exit reason, got %q", closed.Reason)
				}
				if !strings.Contains(output.String(), "terminal-ok") {
					t.Fatalf("expected terminal output to contain command result, got %q", output.String())
				}

				tm.Mu.Lock()
				_, exists := tm.Sessions["sess-1"]
				tm.Mu.Unlock()
				if exists {
					t.Fatalf("expected terminal session cleanup after close")
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for terminal output and close")
		}
	}
}

func TestTerminalManagerLargeOutputEmitsMultipleDataFrames(t *testing.T) {
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	tm := newTerminalManager()
	defer tm.CloseAll()

	startRaw, err := json.Marshal(protocol.TerminalStartData{
		SessionID: "sess-large-output",
		Shell:     shellPath,
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("marshal terminal start: %v", err)
	}

	tm.HandleTerminalStart(transport, protocol.Message{Data: startRaw})
	_ = waitForCapturedAgentMessage(t, messages, protocol.MsgTerminalStarted, 5*time.Second)

	inputRaw, err := json.Marshal(protocol.TerminalDataPayload{
		SessionID: "sess-large-output",
		Data: base64.StdEncoding.EncodeToString([]byte(
			"printf 'BEGIN:'; i=0; while [ $i -lt 6000 ]; do printf x; i=$((i+1)); done; printf ':END\\n'; exit\n",
		)),
	})
	if err != nil {
		t.Fatalf("marshal terminal input: %v", err)
	}
	tm.HandleTerminalData(protocol.Message{Data: inputRaw})

	var (
		output     strings.Builder
		dataFrames int
	)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case msg, ok := <-messages:
			if !ok {
				t.Fatal("transport closed before terminal session finished")
			}
			switch msg.Type {
			case protocol.MsgTerminalData:
				var payload protocol.TerminalDataPayload
				if err := json.Unmarshal(msg.Data, &payload); err != nil {
					t.Fatalf("decode terminal data payload: %v", err)
				}
				decoded, err := base64.StdEncoding.DecodeString(payload.Data)
				if err != nil {
					t.Fatalf("decode terminal data chunk: %v", err)
				}
				dataFrames++
				output.Write(decoded)
			case protocol.MsgTerminalClosed:
				var closed protocol.TerminalCloseData
				if err := json.Unmarshal(msg.Data, &closed); err != nil {
					t.Fatalf("decode terminal closed payload: %v", err)
				}
				if closed.SessionID != "sess-large-output" {
					t.Fatalf("expected closed session_id sess-large-output, got %q", closed.SessionID)
				}
				if !strings.Contains(output.String(), "BEGIN:") || !strings.Contains(output.String(), ":END") {
					t.Fatalf("expected large terminal output markers, got %q", output.String())
				}
				if dataFrames < 2 {
					t.Fatalf("expected large output to span multiple terminal.data frames, got %d", dataFrames)
				}
				if output.Len() < 6000 {
					t.Fatalf("expected collected output length >= 6000 bytes, got %d", output.Len())
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for large terminal output and close")
		}
	}
}

func TestTerminalManagerResizeUpdatesPTYSize(t *testing.T) {
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	tm := newTerminalManager()
	defer tm.CloseAll()

	startRaw, err := json.Marshal(protocol.TerminalStartData{
		SessionID: "sess-resize",
		Shell:     shellPath,
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("marshal terminal start: %v", err)
	}

	tm.HandleTerminalStart(transport, protocol.Message{Data: startRaw})
	_ = waitForCapturedAgentMessage(t, messages, protocol.MsgTerminalStarted, 5*time.Second)

	tm.Mu.Lock()
	sess := tm.Sessions["sess-resize"]
	tm.Mu.Unlock()
	if sess == nil {
		t.Fatal("expected terminal session to exist after start")
	}

	rows, cols, err := pty.Getsize(sess.Ptmx)
	if err != nil {
		t.Fatalf("get initial PTY size: %v", err)
	}
	if rows != 24 || cols != 80 {
		t.Fatalf("initial PTY size=%dx%d, want 24x80", rows, cols)
	}

	resizeRaw, err := json.Marshal(protocol.TerminalResizeData{
		SessionID: "sess-resize",
		Cols:      132,
		Rows:      51,
	})
	if err != nil {
		t.Fatalf("marshal terminal resize: %v", err)
	}
	tm.HandleTerminalResize(protocol.Message{Data: resizeRaw})

	rows, cols, err = pty.Getsize(sess.Ptmx)
	if err != nil {
		t.Fatalf("get resized PTY size: %v", err)
	}
	if rows != 51 || cols != 132 {
		t.Fatalf("resized PTY size=%dx%d, want 51x132", rows, cols)
	}

	closeRaw, err := json.Marshal(protocol.TerminalCloseData{SessionID: "sess-resize"})
	if err != nil {
		t.Fatalf("marshal terminal close: %v", err)
	}
	tm.HandleTerminalClose(protocol.Message{Data: closeRaw})

	closedMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgTerminalClosed, 5*time.Second)
	var closed protocol.TerminalCloseData
	if err := json.Unmarshal(closedMsg.Data, &closed); err != nil {
		t.Fatalf("decode terminal closed payload: %v", err)
	}
	if closed.SessionID != "sess-resize" {
		t.Fatalf("expected closed session_id sess-resize, got %q", closed.SessionID)
	}

	tm.Mu.Lock()
	_, exists := tm.Sessions["sess-resize"]
	tm.Mu.Unlock()
	if exists {
		t.Fatal("expected terminal session cleanup after explicit close")
	}
}

func TestTerminalManagerRejectsStartWhenSessionLimitReached(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	tm := newTerminalManager()
	for i := 0; i < maxTerminalSessions; i++ {
		tm.Sessions[string(rune('a'+i))] = nil
	}

	startRaw, err := json.Marshal(protocol.TerminalStartData{SessionID: "overflow"})
	if err != nil {
		t.Fatalf("marshal terminal start: %v", err)
	}
	tm.HandleTerminalStart(transport, protocol.Message{Data: startRaw})

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgTerminalClosed, 2*time.Second)
	var closed protocol.TerminalCloseData
	if err := json.Unmarshal(msg.Data, &closed); err != nil {
		t.Fatalf("decode terminal closed payload: %v", err)
	}
	if !strings.Contains(closed.Reason, "max terminal sessions reached") {
		t.Fatalf("expected max-session rejection, got %q", closed.Reason)
	}
}

func newAgentcoreCapturedTransport(t *testing.T) (*wsTransport, <-chan protocol.Message, func()) {
	t.Helper()

	serverConnCh := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		serverConnCh <- conn
	}))

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial failed: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		server.Close()
		t.Fatal("timed out waiting for websocket capture connection")
	}

	messageCh := make(chan protocol.Message, 64)
	go func() {
		defer close(messageCh)
		for {
			var msg protocol.Message
			if err := serverConn.ReadJSON(&msg); err != nil {
				return
			}
			messageCh <- msg
		}
	}()

	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		server.Close()
	}
	return &wsTransport{conn: clientConn}, messageCh, cleanup
}

func waitForCapturedAgentMessage(t *testing.T, messages <-chan protocol.Message, wantType string, timeout time.Duration) protocol.Message {
	t.Helper()

	deadline := time.After(timeout)
	for {
		select {
		case msg, ok := <-messages:
			if !ok {
				t.Fatalf("capture channel closed before %s arrived", wantType)
			}
			if msg.Type == wantType {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", wantType)
		}
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve temp dir %q: %v", root, err)
	}
	return resolved
}
