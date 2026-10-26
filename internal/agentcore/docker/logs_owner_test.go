package docker

import (
	"context"
	"encoding/json"
	"github.com/labtether/protocol"
	"net/http"
	"testing"
	"time"
)

func TestDockerLogsPreparedStopCancelsCreateAndPreservesReplacement(t *testing.T) {
	entered := make(chan struct{})
	server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()
	manager := NewDockerLogManager(client)
	defer manager.CloseAll()
	sender := newRecordingCollectorTransport(true)
	raw, _ := json.Marshal(protocol.DockerLogsStartData{SessionID: "same", ContainerID: "ct-1", Follow: true})
	msg := protocol.Message{Data: raw}
	start := manager.PrepareLogsStart(context.Background(), sender, msg)
	if start == nil {
		t.Fatal("start not reserved")
	}
	manager.mu.Lock()
	old := manager.streams["same"]
	manager.mu.Unlock()
	if manager.PrepareLogsStart(context.Background(), sender, msg) != nil {
		t.Fatal("duplicate log stream accepted")
	}
	start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("log request not started")
	}
	stopRaw, _ := json.Marshal(protocol.DockerLogsStopData{SessionID: "same"})
	manager.HandleLogsStop(protocol.Message{Data: stopRaw})
	if manager.PrepareLogsStart(context.Background(), sender, msg) == nil {
		t.Fatal("replacement rejected")
	}
	manager.mu.Lock()
	replacement := manager.streams["same"]
	manager.mu.Unlock()
	select {
	case <-old.done:
	case <-time.After(time.Second):
		t.Fatal("old log request was not canceled")
	}
	manager.mu.Lock()
	kept := manager.streams["same"] == replacement
	manager.mu.Unlock()
	if !kept {
		t.Fatal("old log cleanup removed replacement")
	}
	if sender.MessageCount() != 0 {
		t.Fatal("canceled logs emitted data")
	}
}
