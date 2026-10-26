package remoteaccess

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestWebRTCSharedInputPhysicalX11Aliases(t *testing.T) {
	registry, recorder := &webRTCInputRegistry{}, &sharedInputRecorder{}
	var mu sync.Mutex
	keymap, queries := testX11Keymap, 0
	resolve := func(_ context.Context, event WebRTCInputEvent) (WebRTCInputEvent, error) {
		if event.Type != "keydown" {
			return event, nil
		}
		mu.Lock()
		defer mu.Unlock()
		queries++
		key, _ := X11KeyArgument(event)
		code, err := resolveX11Keycode([]byte(keymap), key)
		event.x11Keycode = code
		return event, err
	}
	sendFirst, stopFirst := startSharedInputController(t, registry, recorder, ":0", nil, resolve)
	sendSecond, stopSecond := startSharedInputController(t, registry, recorder, ":0.1", nil, resolve)
	sendFirst(WebRTCInputEvent{Type: "keydown", Code: "ShiftLeft"})
	sendSecond(WebRTCInputEvent{Type: "keydown", KeyCode: 0xffe1}, WebRTCInputEvent{Type: "keydown", Code: "ShiftRight"})
	stopFirst()
	if got := recorder.snapshot(); !reflect.DeepEqual(got, []string{"keydown:x11-keycode:50", "keydown:x11-keycode:50", "keydown:x11-keycode:62"}) {
		t.Fatalf("named controller released another alias or modifier: %v", got)
	}
	sendSecond(WebRTCInputEvent{Type: "keyup", Code: "ShiftRight"})
	want := []string{"keydown:x11-keycode:50", "keydown:x11-keycode:50", "keydown:x11-keycode:62", "keyup:x11-keycode:62"}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("right shift released left shift: %v", got)
	}
	stopSecond()
	want = append(want, "keyup:x11-keycode:50")
	if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("final alias release=%v", got)
	}
	mu.Lock()
	if queries != 3 {
		t.Errorf("releases unexpectedly queried changed keymap: %d queries", queries)
	}
	mu.Unlock()
}

func TestWebRTCSharedInputPinsX11PressAcrossKeymapChanges(t *testing.T) {
	registry, recorder := &webRTCInputRegistry{}, &sharedInputRecorder{}
	var mu sync.Mutex
	keymap, queries := testX11Keymap, 0
	resolve := func(_ context.Context, event WebRTCInputEvent) (WebRTCInputEvent, error) {
		if event.Type != "keydown" {
			return event, nil
		}
		mu.Lock()
		defer mu.Unlock()
		queries++
		key, _ := X11KeyArgument(event)
		code, err := resolveX11Keycode([]byte(keymap), key)
		event.x11Keycode = code
		return event, err
	}
	send, stop := startSharedInputController(t, registry, recorder, ":0", nil, resolve)
	send(WebRTCInputEvent{Type: "keydown", Code: "KeyA"}, WebRTCInputEvent{Type: "keydown", KeyCode: 0x61})
	send(WebRTCInputEvent{Type: "keyup", Code: "KeyA"})
	if len(recorder.snapshot()) != 2 {
		t.Fatal("same owner's alias lifted its other hold")
	}
	mu.Lock()
	keymap = strings.Replace(testX11Keymap, "38 0x0061", "54 0x0061", 1)
	mu.Unlock()
	send(WebRTCInputEvent{Type: "keydown", KeyCode: 0x61}, WebRTCInputEvent{Type: "keyup", KeyCode: 0x61}, WebRTCInputEvent{Type: "keydown", Code: "KeyA"})
	stop()
	want := []string{"keydown:x11-keycode:38", "keydown:x11-keycode:38", "keydown:x11-keycode:38", "keyup:x11-keycode:38", "keydown:x11-keycode:54", "keyup:x11-keycode:54"}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("layout switch redirected an existing hold: %v", got)
	}
	mu.Lock()
	if queries != 3 {
		t.Errorf("expected each new press to resolve once, got %d", queries)
	}
	mu.Unlock()
	if len(registry.targets) != 0 {
		t.Fatal("layout change leaked target ownership")
	}
}
