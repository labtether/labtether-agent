package remoteaccess

import (
	"context"
	"encoding/json"
	"github.com/creack/pty"
	"github.com/labtether/protocol"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type terminalStartMessages struct {
	ctx      context.Context
	mu       sync.Mutex
	messages []protocol.Message
}

func (s *terminalStartMessages) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
func (s *terminalStartMessages) Send(msg protocol.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
	return nil
}

func TestTerminalStartReservationCloseBeforeWorker(t *testing.T) {
	manager := NewTerminalManager()
	defer manager.CloseAll()
	calls := 0
	manager.startPTY = func(*exec.Cmd, *pty.Winsize) (*os.File, error) {
		calls++
		t.Error("canceled startup launched shell")
		return nil, os.ErrClosed
	}
	sender := &terminalStartMessages{}
	raw, _ := json.Marshal(protocol.TerminalStartData{SessionID: "ordered", Shell: "sh"})
	start := manager.PrepareTerminalStart(sender, protocol.Message{Data: raw})
	if start == nil {
		t.Fatal("start was not reserved")
	}
	if manager.PrepareTerminalStart(sender, protocol.Message{Data: raw}) != nil {
		t.Fatal("duplicate startup was accepted")
	}
	closeRaw, _ := json.Marshal(protocol.TerminalCloseData{SessionID: "ordered"})
	manager.HandleTerminalClose(protocol.Message{Data: closeRaw})
	start()
	if calls != 0 || len(manager.Sessions) != 0 || len(manager.pending) != 0 {
		t.Fatal("closed pending start left work behind")
	}
}

func TestTerminalStartReservationCancelsLateResourceAndPreservesReplacement(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "close all"}[all], func(t *testing.T) {
			manager := NewTerminalManager()
			defer manager.CloseAll()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			file, peer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			defer peer.Close()
			manager.startPTY = func(*exec.Cmd, *pty.Winsize) (*os.File, error) { close(entered); <-release; return file, nil }
			sender := &terminalStartMessages{}
			raw, _ := json.Marshal(protocol.TerminalStartData{SessionID: "same", Shell: "sh"})
			start := manager.PrepareTerminalStart(sender, protocol.Message{Data: raw})
			done := make(chan struct{})
			go func() { defer close(done); start() }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("startup never reached resource creation")
			}
			if manager.PrepareTerminalStart(sender, protocol.Message{Data: raw}) != nil {
				t.Fatal("duplicate startup was accepted")
			}
			if all {
				manager.CloseAll()
			} else {
				closeRaw, _ := json.Marshal(protocol.TerminalCloseData{SessionID: "same"})
				manager.HandleTerminalClose(protocol.Message{Data: closeRaw})
			}
			if manager.PrepareTerminalStart(sender, protocol.Message{Data: raw}) == nil {
				t.Fatal("fresh reservation was rejected after close")
			}
			manager.Mu.Lock()
			replacement := manager.pending["same"]
			manager.Mu.Unlock()
			unblock()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("canceled startup did not finish")
			}
			if _, err := file.Stat(); err == nil {
				t.Fatal("late startup leaked its resource")
			}
			if len(manager.Sessions) != 0 || manager.pending["same"] != replacement {
				t.Fatal("old startup published or removed replacement")
			}
			sender.mu.Lock()
			defer sender.mu.Unlock()
			if len(sender.messages) != 0 {
				t.Fatalf("old startup sent state after cancellation: %v", sender.messages)
			}
		})
	}
}

func TestTerminalStartReservationSocketCancellationBeforeWorker(t *testing.T) {
	manager := NewTerminalManager()
	defer manager.CloseAll()
	manager.startPTY = func(*exec.Cmd, *pty.Winsize) (*os.File, error) {
		t.Error("old socket launched a shell")
		return nil, os.ErrClosed
	}
	ctx, cancel := context.WithCancel(context.Background())
	raw, _ := json.Marshal(protocol.TerminalStartData{SessionID: "old-socket", Shell: "sh"})
	start := manager.PrepareTerminalStart(&terminalStartMessages{ctx: ctx}, protocol.Message{Data: raw})
	if start == nil {
		t.Fatal("start not reserved")
	}
	cancel()
	start()
	if len(manager.Sessions) != 0 || len(manager.pending) != 0 {
		t.Fatal("socket cancellation left owner behind")
	}
}

func (s *terminalStartMessages) snapshot() []protocol.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Message(nil), s.messages...)
}
