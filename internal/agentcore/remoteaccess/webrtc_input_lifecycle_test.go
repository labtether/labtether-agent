package remoteaccess

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/x11input"
	"github.com/labtether/protocol"
)

func TestWebRTCInputOverflowReleasesHeldKeyOnBothRoutes(t *testing.T) {
	for _, route := range []string{"websocket", "data-channel"} {
		t.Run(route, func(t *testing.T) {
			manager := NewWebRTCManager(protocol.WebRTCCapabilitiesData{}, nil, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sess := &WebRTCSession{sessionID: "overflow", inputCh: make(chan WebRTCInputEvent, 1), inputDone: make(chan struct{}), done: make(chan struct{}), cancel: cancel}
			manager.Sessions[sess.sessionID] = sess
			transport, messages, cleanup := newDesktopRuntimeTransport(t)
			defer cleanup()
			defer manager.CloseAll()
			sess.onInputFailure = func(reason string) { manager.failWebRTCInput(transport, sess, reason) }
			pressed := make(chan struct{})
			released := make(chan error, 1)
			go func() {
				defer close(sess.inputDone)
				runWebRTCInputEvents(ctx, sess.inputCh, sess, func(inputCtx context.Context, event WebRTCInputEvent) error {
					if event.Type == "keydown" {
						close(pressed)
						<-inputCtx.Done()
						return inputCtx.Err()
					}
					if event.Type == "keyup" && event.Code == "KeyA" {
						released <- inputCtx.Err()
						return nil
					}
					return errors.New("queued movement ran after input failure")
				})
			}()
			send := func(evt WebRTCInputEvent) {
				if route == "data-channel" {
					manager.enqueueWebRTCInput(transport, sess, evt)
					return
				}
				raw, _ := json.Marshal(protocol.WebRTCInputData{SessionID: sess.sessionID, Type: evt.Type, Code: evt.Code})
				manager.HandleWebRTCInput(protocol.Message{Type: protocol.MsgWebRTCInput, Data: raw}, transport)
			}
			send(WebRTCInputEvent{Type: "keydown", Code: "KeyA"})
			select {
			case <-pressed:
			case <-time.After(time.Second):
				t.Fatal("keydown was not injected")
			}
			send(WebRTCInputEvent{Type: "mousemove"})
			returned := make(chan struct{})
			go func() {
				send(WebRTCInputEvent{Type: "keyup", Code: "KeyA"})
				close(returned)
			}()
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("overflow blocked its ingress reader")
			}
			select {
			case err := <-released:
				if err != nil {
					t.Fatalf("release inherited canceled context: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("held key was not released after overflow")
			}
			msg := readDesktopRuntimeMessage(t, messages)
			var stopped protocol.WebRTCStoppedData
			if err := json.Unmarshal(msg.Data, &stopped); err != nil || msg.Type != protocol.MsgWebRTCStopped || !strings.Contains(stopped.Reason, "input queue full") {
				t.Fatalf("missing explicit failure response: type=%s payload=%+v error=%v", msg.Type, stopped, err)
			}
		})
	}
}

func TestWebRTCInputCleanupTracksRepeatedAndReleasedInputs(t *testing.T) {
	ch := make(chan WebRTCInputEvent, 5)
	for _, evt := range []WebRTCInputEvent{
		{Type: "keydown", Code: "KeyA"}, {Type: "keydown", Code: "KeyA"},
		{Type: "mousedown", Button: 0}, {Type: "mouseup", Button: 0},
		{Type: "mousemove"},
	} {
		ch <- evt
	}
	close(ch)
	var events []string
	runWebRTCInputEvents(context.Background(), ch, nil, func(_ context.Context, evt WebRTCInputEvent) error {
		events = append(events, evt.Type)
		return nil
	})
	want := []string{"keydown", "keydown", "mousedown", "mouseup", "mousemove", "keyup"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("input/release sequence=%v, want %v", events, want)
	}
}

func TestWebRTCInputCleanupReleasesPossiblyPressedButtonAfterError(t *testing.T) {
	ch := make(chan WebRTCInputEvent, 1)
	ch <- WebRTCInputEvent{Type: "mousedown", Button: 2}
	close(ch)
	var events []string
	runWebRTCInputEvents(context.Background(), ch, nil, func(ctx context.Context, evt WebRTCInputEvent) error {
		events = append(events, evt.Type)
		if evt.Type == "mousedown" {
			return errors.New("helper failed after pressing")
		}
		if ctx.Err() != nil || evt.Button != 2 {
			t.Fatalf("wrong release: %+v %v", evt, ctx.Err())
		}
		return nil
	})
	if !reflect.DeepEqual(events, []string{"mousedown", "mouseup"}) {
		t.Fatalf("failed press/release sequence=%v", events)
	}
}

func TestWebRTCInputCanceledHelperIsReaped(t *testing.T) {
	if os.Getenv("LABTETHER_TEST_INPUT_HELPER") == "1" {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	original, originalInternal := NewWebRTCSecurityCommand, NewWebRTCInternalX11Command
	t.Cleanup(func() {
		NewWebRTCSecurityCommand, NewWebRTCInternalX11Command = original, originalInternal
	})
	for _, name := range []string{"xdotool", x11input.PolicyName} {
		t.Run(name, func(t *testing.T) {
			var child *exec.Cmd
			makeChild := func(...string) (*exec.Cmd, error) {
				child = exec.Command(executable, "-test.run=^TestWebRTCInputCanceledHelperIsReaped$")
				return child, nil
			}
			NewWebRTCSecurityCommand = func(string, ...string) (*exec.Cmd, error) { return makeChild() }
			NewWebRTCInternalX11Command = makeChild
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := runWebRTCInputCommandContext(ctx, name, append(os.Environ(), "LABTETHER_TEST_INPUT_HELPER=1"), "down", "50")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("helper error=%v, want deadline", err)
			}
			if child == nil || child.ProcessState == nil {
				t.Fatal("canceled input helper was not reaped")
			}
		})
	}
}
