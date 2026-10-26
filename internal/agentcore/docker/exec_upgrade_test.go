package docker

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestDockerExecSetupBudgetDoesNotLimitDuplexSession(t *testing.T) {
	peerDone := make(chan error, 1)
	server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/ct-1/exec" {
			_, _ = w.Write([]byte(`{"Id":"live-exec"}`))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		_ = rw.Flush()
		text, err := rw.ReadString('\n')
		if err != nil {
			peerDone <- err
			return
		}
		_, _ = rw.WriteString("echo " + text)
		_ = rw.Flush()
		_, err = rw.ReadByte() // Explicit close must terminate the live upgrade.
		peerDone <- err
	}))
	defer server.Close()
	client.httpClient.Timeout = 30 * time.Second // Production default hides Writer unless removed.
	manager := NewDockerExecManager(client)
	manager.setupTimeout = 500 * time.Millisecond
	defer manager.CloseAll()
	sender := newRecordingCollectorTransport(true)
	raw, _ := json.Marshal(protocol.DockerExecStartData{SessionID: "live", ContainerID: "ct-1", TTY: true})
	manager.HandleExecStart(sender, protocol.Message{Data: raw})
	if message := waitForCollectorMessage(t, sender, time.Second); message.Type != protocol.MsgDockerExecStarted {
		t.Fatalf("upgrade did not start: %s %s", message.Type, message.Data)
	}
	// Cross the setup deadline before either direction carries stream data.
	<-time.After(manager.setupTimeout + 50*time.Millisecond)
	input, _ := json.Marshal(protocol.DockerExecInputData{SessionID: "live", Data: base64.StdEncoding.EncodeToString([]byte("still open\n"))})
	manager.HandleExecInput(protocol.Message{Data: input})
	message := waitForCollectorMessage(t, sender, time.Second)
	var data protocol.DockerExecDataPayload
	if message.Type != protocol.MsgDockerExecData || json.Unmarshal(message.Data, &data) != nil {
		t.Fatalf("duplex output missing after setup deadline: %s %s", message.Type, message.Data)
	}
	decoded, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil || string(decoded) != "echo still open\n" {
		t.Fatalf("echo=%q err=%v", decoded, err)
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Fatal("shared client timeout was mutated")
	}
	manager.CloseAll()
	select {
	case err := <-peerDone:
		if err != io.EOF {
			t.Fatalf("peer close=%v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session close did not reach upgraded peer")
	}
}

func TestDockerExecSetupBudgetCancelsStalledUpgrade(t *testing.T) {
	canceled := make(chan struct{})
	server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/ct-1/exec" {
			_, _ = w.Write([]byte(`{"Id":"stalled-exec"}`))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()
	manager := NewDockerExecManager(client)
	manager.setupTimeout = 100 * time.Millisecond
	defer manager.CloseAll()
	sender := newRecordingCollectorTransport(true)
	raw, _ := json.Marshal(protocol.DockerExecStartData{SessionID: "stalled", ContainerID: "ct-1", TTY: true})
	manager.HandleExecStart(sender, protocol.Message{Data: raw})
	message := waitForCollectorMessage(t, sender, time.Second)
	if message.Type != protocol.MsgDockerExecClosed || !strings.Contains(string(message.Data), "startup timed out") {
		t.Fatalf("timeout did not fail visibly: %s %s", message.Type, message.Data)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("stalled upgrade was not canceled")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.sessions) != 0 || len(manager.pending) != 0 {
		t.Fatal("timed out startup retained an owner")
	}
}
