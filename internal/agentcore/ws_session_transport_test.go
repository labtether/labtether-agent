package agentcore

import (
	"context"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/labtether/protocol"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestReconnectPublicationWaitsForCleanupAndRejectsOldSocket(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	peers := make(chan *websocket.Conn, 2)
	messages := make(chan protocol.Message, 2)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		peers <- conn
		for {
			var msg protocol.Message
			if conn.ReadJSON(&msg) != nil {
				return
			}
			messages <- msg
		}
	}))
	defer server.Close()
	transport := newWSTransport("ws"+server.URL[len("http"):], "token", "node-1", "linux", "test", nil, "", nil)
	defer transport.Close()
	if err := transport.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldPeer := <-peers
	transport.mu.Lock()
	oldConn := transport.conn
	transport.mu.Unlock()
	var oldSender *sessionMessageSender
	transport.withCurrentSessionMessage(oldConn, func(sender *sessionMessageSender) { oldSender = sender })
	_ = oldPeer.Close()
	_, _, failedConn, readErr := transport.receiveWithConnection()
	if readErr == nil || failedConn != oldConn {
		t.Fatal("old read did not keep socket identity")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	transport.beforeConnect = func() { close(entered); <-release }
	connected := make(chan error, 1)
	go func() { connected <- transport.Connect(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup was not called")
	}
	if transport.Connected() || transport.socketOpen() {
		t.Error("replacement published before cleanup finished")
	}
	if oldSender.Context().Err() == nil {
		t.Error("old session context was not canceled before cleanup")
	}
	unblock()
	select {
	case err := <-connected:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not publish")
	}
	newPeer := <-peers
	defer newPeer.Close()
	transport.markDisconnectedIfCurrent(failedConn)
	if !transport.Connected() {
		t.Fatal("old read error disconnected replacement")
	}
	if !errors.Is(oldSender.Send(protocol.Message{Type: "old-session"}), errNotConnected) {
		t.Fatal("old sender accepted output on replacement")
	}
	staleDispatched := false
	transport.withCurrentSessionMessage(oldConn, func(*sessionMessageSender) { staleDispatched = true })
	if staleDispatched {
		t.Fatal("old frame reached session owner after cleanup")
	}
	if err := transport.Send(protocol.Message{Type: "fresh-session"}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-messages:
		if msg.Type != "fresh-session" {
			t.Fatalf("replacement received stale output: %s", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement send failed")
	}
}
