package remoteaccess

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestWebRTCReleaseWaitsForFullInputQueue(t *testing.T) {
	sess := &WebRTCSession{inputCh: make(chan WebRTCInputEvent, 1), done: make(chan struct{})}
	sess.inputCh <- WebRTCInputEvent{Type: "mousemove", X: 10}
	finished := make(chan bool, 1)
	go func() { finished <- sess.queueInputEvent(WebRTCInputEvent{Type: "keyup", Code: "ShiftLeft"}) }()
	select {
	case <-finished:
		t.Fatal("release was dropped instead of waiting for queue capacity")
	case <-time.After(20 * time.Millisecond):
	}
	<-sess.inputCh
	select {
	case accepted := <-finished:
		if !accepted {
			t.Fatal("release was rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("release stayed blocked")
	}
	select {
	case event := <-sess.inputCh:
		if event.Type != "keyup" || event.Code != "ShiftLeft" {
			t.Fatalf("wrong queued event: %+v", event)
		}
	default:
		t.Fatal("key release was silently dropped")
	}
}

func TestWebRTCStaleInputCannotReleaseNewSessionKeys(t *testing.T) {
	checkWebRTCStaleInputOwnership(t, ":stale-test", ":stale-test")
}

func TestWebRTCStaleInputCannotReleaseAliasedScreenKeys(t *testing.T) {
	for _, pair := range [][2]string{{":93", ":93.0"}, {":93.0", ":93.1"}, {":093.1", ":93"}} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) { checkWebRTCStaleInputOwnership(t, pair[0], pair[1]) })
	}
}

func checkWebRTCStaleInputOwnership(t *testing.T, oldDisplay, newDisplay string) {
	t.Helper()
	original := NewWebRTCSecurityCommand
	t.Cleanup(func() { NewWebRTCSecurityCommand = original })
	var calls [][]string
	NewWebRTCSecurityCommand = func(_ string, args ...string) (*exec.Cmd, error) {
		calls = append(calls, append([]string(nil), args...))
		return exec.Command(os.Args[0], "-test.run=^$"), nil
	}
	old, current := &WebRTCSession{}, &WebRTCSession{}
	oldState, currentState := &webRTCPressedInput{}, &webRTCPressedInput{}
	t.Cleanup(func() {
		oldState.release(oldDisplay, "", old)
		currentState.release(newDisplay, "", current)
	})
	for _, evt := range []WebRTCInputEvent{{Type: "keydown", Code: "ShiftLeft"}, {Type: "mousedown", Button: 0}} {
		oldState.observe(evt)
		if err := injectOwnedWebRTCInput(context.Background(), evt, oldDisplay, "", old); err != nil {
			t.Fatal(err)
		}
		currentState.observe(evt)
		if err := injectOwnedWebRTCInput(context.Background(), evt, newDisplay, "", current); err != nil {
			t.Fatal(err)
		}
	}
	if err := injectOwnedWebRTCInput(context.Background(), WebRTCInputEvent{Type: "keyup", Code: "ShiftLeft"}, oldDisplay, "", old); err != nil {
		t.Fatal(err)
	}
	oldState.release(oldDisplay, "", old)
	if len(calls) != 4 {
		t.Fatalf("old session released new input: %v", calls)
	}
	currentState.release(newDisplay, "", current)
	want := [][]string{{"keyup", "Shift_L"}, {"mouseup", "1"}}
	if !reflect.DeepEqual(calls[4:], want) {
		t.Fatalf("new session releases=%v, want %v", calls[4:], want)
	}
}

func TestWebRTCInputDisconnectReleasesOnlyItsPressedState(t *testing.T) {
	original := NewWebRTCSecurityCommand
	t.Cleanup(func() { NewWebRTCSecurityCommand = original })
	var calls [][]string
	NewWebRTCSecurityCommand = func(_ string, args ...string) (*exec.Cmd, error) {
		calls = append(calls, append([]string(nil), args...))
		return exec.Command(os.Args[0], "-test.run=^$"), nil
	}
	events := make(chan WebRTCInputEvent, 2)
	events <- WebRTCInputEvent{Type: "keydown", Code: "ShiftLeft"}
	events <- WebRTCInputEvent{Type: "mousedown", Button: 0}
	close(events)
	InjectInputEvents(context.Background(), events, ":0", "", &WebRTCSession{})
	want := [][]string{{"keydown", "Shift_L"}, {"mousedown", "1"}, {"keyup", "Shift_L"}, {"mouseup", "1"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("input cleanup=%v, want %v", calls, want)
	}
}

func TestWebRTCReleasedKeysAreNotReleasedAgainOnDisconnect(t *testing.T) {
	state := &webRTCPressedInput{}
	state.observe(WebRTCInputEvent{Type: "keydown", Code: "KeyA", Key: "A"})
	state.observe(WebRTCInputEvent{Type: "keyup", Code: "KeyA", Key: "a"})
	if len(state.keys) != 0 {
		t.Fatal("physical key release depended on shifted text")
	}
}
