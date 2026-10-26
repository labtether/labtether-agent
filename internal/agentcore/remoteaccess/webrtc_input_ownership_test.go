package remoteaccess

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type sharedInputRecorder struct {
	mu     sync.Mutex
	events []string
	fail   bool
}

func (r *sharedInputRecorder) inject(_ context.Context, event WebRTCInputEvent) error {
	if event.Type != "mousemove" {
		r.mu.Lock()
		r.events = append(r.events, event.Type+":"+webRTCHeldInputKey(event, nil))
		r.mu.Unlock()
	}
	return nil
}

func (r *sharedInputRecorder) release(ctx context.Context, events []WebRTCInputEvent) error {
	r.mu.Lock()
	fail := r.fail
	r.mu.Unlock()
	if fail {
		return errors.New("input backend unavailable")
	}
	for _, event := range events {
		if err := r.inject(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func (r *sharedInputRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func startSharedInputController(t *testing.T, registry *webRTCInputRegistry, recorder *sharedInputRecorder, display string, sess *WebRTCSession, resolvers ...webRTCInputResolver) (func(...WebRTCInputEvent), func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan WebRTCInputEvent, 10)
	ack, done := make(chan struct{}, 1), make(chan struct{})
	go func() {
		defer close(done)
		runSharedWebRTCInputEvents(ctx, ch, display, sess, registry, func(ctx context.Context, event WebRTCInputEvent) error {
			err := recorder.inject(ctx, event)
			if event.Type == "mousemove" {
				ack <- struct{}{}
			}
			return err
		}, recorder.release, resolvers...)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("shared input worker did not stop")
		}
	}
	t.Cleanup(stop)
	send := func(events ...WebRTCInputEvent) {
		t.Helper()
		for _, event := range events {
			ch <- event
		}
		ch <- WebRTCInputEvent{Type: "mousemove"}
		select {
		case <-ack:
		case <-done:
			t.Fatal("shared input worker failed before the input barrier")
		case <-time.After(time.Second):
			t.Fatal("shared input worker did not reach the input barrier")
		}
	}
	return send, stop
}

func TestWebRTCSharedInputControllersRetainEachOthersHolds(t *testing.T) {
	for _, backend := range []string{"x11", "wayland"} {
		t.Run(backend, func(t *testing.T) {
			registry, recorder := &webRTCInputRegistry{}, &sharedInputRecorder{}
			first, second := &WebRTCSession{}, &WebRTCSession{}
			if backend == "wayland" {
				first.sessionInfo = DesktopSessionInfo{Type: DesktopSessionTypeWayland, WaylandDisplay: "wayland-0"}
				second.sessionInfo = DesktopSessionInfo{Type: DesktopSessionTypeWayland, WaylandDisplay: "wayland-1"}
			}
			sendFirst, stopFirst := startSharedInputController(t, registry, recorder, ":01.0", first)
			sendSecond, stopSecond := startSharedInputController(t, registry, recorder, ":1.1", second)
			key := WebRTCInputEvent{Type: "keydown", Code: "ShiftLeft"}
			button := WebRTCInputEvent{Type: "mousedown", Button: 0}
			sendFirst(key, key, button) // repeats still reach the physical backend
			sendSecond(key, button)
			sendFirst(WebRTCInputEvent{Type: "keyup", Code: "ShiftLeft"})
			stopFirst() // the remaining mouse hold also belongs to controller two
			if got := recorder.snapshot(); len(got) != 5 {
				t.Fatalf("first controller released shared state: %v", got)
			}
			sendSecond(WebRTCInputEvent{Type: "keyup", Code: "ShiftLeft"}, WebRTCInputEvent{Type: "mouseup", Button: 0})
			stopSecond()
			want := []string{"keydown:key:Shift_L", "keydown:key:Shift_L", "mousedown:button:0", "keydown:key:Shift_L", "mousedown:button:0", "keyup:key:Shift_L", "mouseup:button:0"}
			if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("physical input sequence=%v, want %v", got, want)
			}
			if len(registry.targets) != 0 {
				t.Fatal("released controllers retained a target")
			}
		})
	}
}

func TestWebRTCSharedInputFailedCleanupTransfersOrRetriesDebt(t *testing.T) {
	for _, next := range []string{"same-key", "movement"} {
		t.Run(next, func(t *testing.T) {
			registry, recorder := &webRTCInputRegistry{}, &sharedInputRecorder{}
			sendOld, stopOld := startSharedInputController(t, registry, recorder, ":0", nil)
			key := WebRTCInputEvent{Type: "keydown", Code: "KeyA"}
			sendOld(key)
			recorder.mu.Lock()
			recorder.fail = true
			recorder.mu.Unlock()
			stopOld()
			if len(registry.targets) != 1 {
				t.Fatal("failed cleanup forgot the physical input debt")
			}
			recorder.mu.Lock()
			recorder.fail = false
			recorder.mu.Unlock()
			sendNew, stopNew := startSharedInputController(t, registry, recorder, ":0.1", nil)
			want := []string{"keydown:key:a", "keyup:key:a"}
			if next == "same-key" {
				sendNew(key)
				if got := recorder.snapshot(); !reflect.DeepEqual(got, []string{"keydown:key:a", "keydown:key:a"}) {
					t.Fatalf("stale cleanup lifted a new hold: %v", got)
				}
				want = []string{"keydown:key:a", "keydown:key:a", "keyup:key:a"}
			} else {
				sendNew()
			}
			stopNew()
			if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("debt recovery=%v, want %v", got, want)
			}
			if len(registry.targets) != 0 {
				t.Fatal("successful retry retained an idle target")
			}
		})
	}
}

func TestWebRTCSharedInputTimedOutRetirementIsDrainedBeforeNewPress(t *testing.T) {
	registry, recorder := &webRTCInputRegistry{}, &sharedInputRecorder{}
	old, err := registry.acquire(":0", nil)
	if err != nil {
		t.Fatal(err)
	}
	key := WebRTCInputEvent{Type: "keydown", Code: "KeyA"}
	if err := old.inject(context.Background(), key, recorder.inject, recorder.release); err != nil {
		t.Fatal(err)
	}
	busy, err := registry.acquire(":0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	entered, unblock, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var unblockOnce sync.Once
	unblockInput := func() { unblockOnce.Do(func() { close(unblock) }) }
	t.Cleanup(unblockInput)
	go func() {
		finished <- busy.inject(context.Background(), WebRTCInputEvent{Type: "mousemove"}, func(context.Context, WebRTCInputEvent) error {
			close(entered)
			<-unblock
			return nil
		}, recorder.release)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("busy controller did not enter physical backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = old.retire(ctx, recorder.release)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy physical target cleanup=%v, want deadline", err)
	}
	registry.release(":0", old)
	sendNew, stopNew := startSharedInputController(t, registry, recorder, ":0", nil)
	unblockInput()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate holder did not drain pending retirement")
	}
	if err := busy.retire(context.Background(), recorder.release); err != nil {
		t.Fatal(err)
	}
	registry.release(":0.1", busy)
	sendNew(key)
	want := []string{"keydown:key:a", "keyup:key:a", "keydown:key:a"}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("old release escaped the physical gate: %v, want %v", got, want)
	}
	stopNew()
}

func TestWebRTCSharedInputDistinctXServersAndUnownedKeyUp(t *testing.T) {
	registry, recorder := &webRTCInputRegistry{}, &sharedInputRecorder{}
	sendFirst, stopFirst := startSharedInputController(t, registry, recorder, ":0", nil)
	sendSecond, stopSecond := startSharedInputController(t, registry, recorder, ":1", nil)
	key := WebRTCInputEvent{Type: "keydown", Code: "KeyA"}
	sendFirst(key)
	sendSecond(WebRTCInputEvent{Type: "keyup", Code: "KeyA"}, key)
	stopFirst()
	if got := recorder.snapshot(); !reflect.DeepEqual(got, []string{"keydown:key:a", "keydown:key:a", "keyup:key:a"}) {
		t.Fatalf("different server input ownership or unowned keyup is wrong: %v", got)
	}
	stopSecond()
}
