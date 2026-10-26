package docker

import (
	"encoding/json"
	"github.com/labtether/protocol"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestDockerExecStartReservationCancelsCreateAndPreservesReplacement(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "close all"}[all], func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-time.After(2 * time.Second):
				}
			}))
			defer server.Close()
			manager := NewDockerExecManager(client)
			defer manager.CloseAll()
			sender := newRecordingCollectorTransport(true)
			raw, _ := json.Marshal(protocol.DockerExecStartData{SessionID: "same", ContainerID: "ct-1"})
			start := manager.PrepareExecStart(sender, protocol.Message{Data: raw})
			if start == nil {
				t.Fatal("start was not reserved")
			}
			done := make(chan struct{})
			go func() { defer close(done); start() }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("create request did not arrive")
			}
			if manager.PrepareExecStart(sender, protocol.Message{Data: raw}) != nil {
				t.Fatal("duplicate create was accepted")
			}
			if all {
				manager.CloseAll()
			} else {
				payload, _ := json.Marshal(protocol.DockerExecCloseData{SessionID: "same"})
				manager.HandleExecClose(protocol.Message{Data: payload})
			}
			if manager.PrepareExecStart(sender, protocol.Message{Data: raw}) == nil {
				t.Fatal("fresh reservation was rejected")
			}
			manager.mu.Lock()
			replacement := manager.pending["same"]
			manager.mu.Unlock()
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("close did not cancel Docker create request")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("canceled create did not finish")
			}
			if calls.Load() != 1 || len(manager.sessions) != 0 || manager.pending["same"] != replacement {
				t.Fatal("old create duplicated work or changed replacement")
			}
			if sender.MessageCount() != 0 {
				t.Fatal("old startup emitted state after cancellation")
			}
		})
	}
}

func TestDockerExecPreparedResizeCannotReachReplacement(t *testing.T) {
	var calls atomic.Int32
	server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	manager := NewDockerExecManager(client)
	manager.sessions["same"] = &dockerExecSession{execID: "old"}
	raw, _ := json.Marshal(protocol.DockerExecResizeData{SessionID: "same", Rows: 40, Cols: 100})
	resize := manager.PrepareExecResize(protocol.Message{Data: raw})
	if resize == nil {
		t.Fatal("resize not prepared")
	}
	manager.sessions["same"] = &dockerExecSession{execID: "replacement"}
	resize()
	if calls.Load() != 0 {
		t.Fatal("old resize issued request after owner replacement")
	}
}
