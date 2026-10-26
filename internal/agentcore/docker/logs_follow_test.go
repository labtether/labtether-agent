package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// The former secured client silently imposed 30 seconds on follow bodies.
// Exercise the real manager past that exact deadline, then prove stop reaches
// the upstream HTTP request and drains the stream owner.
func TestDockerLogManagerFollowOutlivesDefaultHTTPTimeout(t *testing.T) {
	canceled := make(chan struct{})
	server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/ct-1/json" {
			_, _ = w.Write([]byte(`{"Config":{"Tty":false}}`))
			return
		}
		if r.URL.Path != "/containers/ct-1/logs" || r.URL.Query().Get("follow") != "true" {
			http.NotFound(w, r)
			return
		}
		defer close(canceled)
		_, _ = w.Write(dockerMuxFrame(1, "before timeout\n"))
		w.(http.Flusher).Flush()
		timer := time.NewTimer(31 * time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		_, _ = w.Write(dockerMuxFrame(2, "after timeout\n"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer server.Close()
	client.httpClient.Timeout = 30 * time.Second
	manager := NewDockerLogManager(client)
	defer manager.CloseAll()
	sender := newRecordingCollectorTransport(true)
	raw, _ := json.Marshal(protocol.DockerLogsStartData{SessionID: "follow", ContainerID: "ct-1", Follow: true})
	start := manager.PrepareLogsStart(context.Background(), sender, protocol.Message{Data: raw})
	if start == nil {
		t.Fatal("follow was not reserved")
	}
	manager.mu.Lock()
	owner := manager.streams["follow"]
	manager.mu.Unlock()
	start()
	for index, want := range []string{"before timeout", "after timeout"} {
		wait := 2 * time.Second
		if index == 1 {
			wait = 33 * time.Second
		}
		message := waitForCollectorMessage(t, sender, wait)
		var line protocol.DockerLogsStreamData
		if message.Type != protocol.MsgDockerLogsStream || json.Unmarshal(message.Data, &line) != nil || line.Data != want {
			t.Fatalf("follow line %d: %s %s; want %q", index, message.Type, message.Data, want)
		}
	}
	raw, _ = json.Marshal(protocol.DockerLogsStopData{SessionID: "follow"})
	manager.HandleLogsStop(protocol.Message{Data: raw})
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("follow stop did not cancel upstream request")
	}
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("follow owner did not finish")
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Fatal("follow mutated normal request timeout")
	}
}

func TestDockerContainerLogsOneShotRetainsClientTimeout(t *testing.T) {
	canceled := make(chan struct{})
	server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()
	client.httpClient.Timeout = 100 * time.Millisecond
	body, err := client.containerLogs(context.Background(), "ct-1", 10, false, false)
	if err == nil {
		defer body.Close()
		_, err = io.ReadAll(body)
	}
	if err == nil {
		t.Fatal("one-shot logs lost their bounded request timeout")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("one-shot timeout did not close upstream")
	}
}
