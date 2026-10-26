package remoteaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Input is physical state shared by all controllers, including controllers in
// different manager instances. Credentials and an X11 screen number do not
// create a separate keyboard. ydotool injects through one host input device.
var sharedWebRTCInputTargets webRTCInputRegistry

type webRTCInputRegistry struct {
	mu      sync.Mutex
	targets map[string]*webRTCInputTarget
}

type webRTCInputTarget struct {
	gate    chan struct{}
	mu      sync.Mutex
	owners  map[*webRTCInputOwner]map[string]WebRTCInputEvent
	pending map[string]WebRTCInputEvent
	version uint64
	leases  int // protected by registry.mu
}

type webRTCInputOwner struct {
	target   *webRTCInputTarget
	sess     *WebRTCSession
	bindings map[string]WebRTCInputEvent // this reader only; pins logical presses to physical codes
}

func webRTCInputTargetID(display string, sess *WebRTCSession) string {
	if sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland {
		return "ydotool"
	}
	display = strings.TrimSpace(display)
	if display == "" {
		display = ":0"
	}
	if normalized := NormalizeX11DisplayIdentifier(display); normalized != "" {
		number, _, _ := strings.Cut(strings.TrimPrefix(normalized, ":"), ".")
		number = strings.TrimLeft(number, "0")
		if number == "" {
			number = "0"
		}
		return "x11:" + number
	}
	return "x11:" + display
}

func (r *webRTCInputRegistry) acquire(display string, sess *WebRTCSession) (*webRTCInputOwner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.targets == nil {
		r.targets = make(map[string]*webRTCInputTarget)
	}
	id := webRTCInputTargetID(display, sess)
	target := r.targets[id]
	if target == nil {
		// Failed releases remain recorded, even with no live sessions. Bound
		// that retained state and fail explicitly instead of forgetting it.
		if len(r.targets) >= 2*MaxWebRTCSessions {
			return nil, fmt.Errorf("too many input targets awaiting cleanup")
		}
		target = &webRTCInputTarget{gate: make(chan struct{}, 1), owners: make(map[*webRTCInputOwner]map[string]WebRTCInputEvent), pending: make(map[string]WebRTCInputEvent)}
		target.gate <- struct{}{}
		r.targets[id] = target
	}
	target.leases++
	owner := &webRTCInputOwner{target: target, sess: sess, bindings: make(map[string]WebRTCInputEvent)}
	target.mu.Lock()
	target.owners[owner] = make(map[string]WebRTCInputEvent)
	target.mu.Unlock()
	return owner, nil
}

func (r *webRTCInputRegistry) release(display string, owner *webRTCInputOwner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	target := owner.target
	target.leases--
	target.mu.Lock()
	defer target.mu.Unlock()
	if target.leases == 0 && len(target.pending) == 0 {
		delete(r.targets, webRTCInputTargetID(display, owner.sess))
	}
}

func (t *webRTCInputTarget) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.gate:
		if err := ctx.Err(); err != nil {
			t.gate <- struct{}{}
			return err
		}
		return nil
	}
}

// Caller holds mu. A retired controller never keeps another controller's key
// pressed, and a controller cannot send key-up for somebody else's hold.
func (t *webRTCInputTarget) heldByOther(key string, owner *webRTCInputOwner) bool {
	for candidate, held := range t.owners {
		if candidate != owner {
			if _, exists := held[key]; exists {
				return true
			}
		}
	}
	return false
}

// Count distinct physical inputs, including retained release debt. This bound
// cannot grow when active owners retire or repeated keydown events arrive.
func (t *webRTCInputTarget) hasInputCapacity(key string) bool {
	keys := make(map[string]struct{}, len(t.pending))
	for pending := range t.pending {
		keys[pending] = struct{}{}
	}
	for _, held := range t.owners {
		for heldKey := range held {
			keys[heldKey] = struct{}{}
		}
	}
	_, exists := keys[key]
	return exists || len(keys) < maxHeldWebRTCInputs*MaxWebRTCSessions
}

func (o *webRTCInputOwner) inject(ctx context.Context, event WebRTCInputEvent, inject func(context.Context, WebRTCInputEvent) error, release func(context.Context, []WebRTCInputEvent) error, resolvers ...webRTCInputResolver) (err error) {
	t := o.target
	if err = t.lock(ctx); err != nil {
		return err
	}
	var attempted uint64
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), webRTCInputCleanupTimeout)
		defer cancel()
		// A canceled reader immediately retires its own holds below. Leave
		// other debt for that same cleanup budget instead of adding a wait.
		if ctx.Err() != nil {
			cancel()
		}
		err = errors.Join(err, t.unlock(cleanupCtx, attempted, release))
	}()
	logical := webRTCHeldInputKey(event, o.sess)
	down := event.Type == "keydown" || event.Type == "mousedown"
	up := event.Type == "keyup" || event.Type == "mouseup"
	bound, ownsLogical := o.bindings[logical]
	if ownsLogical && (down || up) {
		event.x11Keycode = bound.x11Keycode
	} else if !up && len(resolvers) > 0 && resolvers[0] != nil {
		event, err = resolvers[0](ctx, event)
		if err != nil {
			return err
		}
	}
	key := webRTCHeldInputKey(event, o.sess)
	skip := up && !ownsLogical
	t.mu.Lock()
	held := t.owners[o]
	if key != "" && down {
		if !ownsLogical && len(o.bindings) >= maxHeldWebRTCInputs {
			t.mu.Unlock()
			return fmt.Errorf("too many held inputs")
		}
		if !t.hasInputCapacity(key) {
			t.mu.Unlock()
			return fmt.Errorf("too many inputs awaiting cleanup")
		}
		releaseEvent := event
		if down && event.Type == "keydown" {
			releaseEvent.Type = "keyup"
		} else {
			releaseEvent.Type = "mouseup"
		}
		// Reserve before injection: a canceled helper may already have pressed.
		held[key] = releaseEvent
		o.bindings[logical] = releaseEvent
		// A new live hold takes over failed cleanup for this exact input. No
		// deferred release may then lift the new controller's key.
		delete(t.pending, key)
	} else if key != "" && up {
		otherBinding := o.hasOtherBinding(logical, key)
		skip = skip || otherBinding || t.heldByOther(key, o)
		if skip {
			delete(o.bindings, logical)
			if !otherBinding && ownsLogical {
				delete(held, key)
			}
		}
	}
	t.mu.Unlock()
	attempted, err = t.flush(ctx, release)
	if err != nil || skip {
		return err
	}
	if err = inject(ctx, event); err == nil && up {
		t.mu.Lock()
		delete(held, key)
		delete(o.bindings, logical)
		t.mu.Unlock()
	}
	return err
}

func (o *webRTCInputOwner) hasOtherBinding(logical, physical string) bool {
	for key, event := range o.bindings {
		if key != logical && webRTCHeldInputKey(event, o.sess) == physical {
			return true
		}
	}
	return false
}

// Retirement never waits while holding the state mutex. If the physical gate
// is busy past the cleanup deadline, release debt remains for its current
// holder (or the next input turn); no detached goroutine waits on the lock.
func (o *webRTCInputOwner) retire(ctx context.Context, release func(context.Context, []WebRTCInputEvent) error) error {
	t := o.target
	t.mu.Lock()
	for key, event := range t.owners[o] {
		if !t.heldByOther(key, o) {
			t.pending[key] = event
			t.version++
		}
	}
	delete(t.owners, o)
	t.mu.Unlock()
	if err := t.lock(ctx); err != nil {
		return err
	}
	attempted, err := t.flush(ctx, release)
	return errors.Join(err, t.unlock(ctx, attempted, release))
}

// Caller owns the physical gate. Owners may retire concurrently, but cannot
// press or release anything until this batch has finished and been reaped.
func (t *webRTCInputTarget) flush(ctx context.Context, release func(context.Context, []WebRTCInputEvent) error) (uint64, error) {
	t.mu.Lock()
	version := t.version
	events := make([]WebRTCInputEvent, 0, len(t.pending))
	keys := make([]string, 0, len(t.pending))
	for key, event := range t.pending {
		keys = append(keys, key)
		events = append(events, event)
	}
	t.mu.Unlock()
	if len(events) == 0 {
		return version, nil
	}
	if err := release(ctx, events); err != nil {
		return version, err
	}
	t.mu.Lock()
	for _, key := range keys {
		delete(t.pending, key)
	}
	t.mu.Unlock()
	return version, nil
}

// Drain retirements that arrived during this owner's physical call. The gate
// release and last debt check share mu with retire, so a timed-out retiree
// cannot disappear in the gap. One fresh budget bounds all extra batches.
func (t *webRTCInputTarget) unlock(ctx context.Context, attempted uint64, release func(context.Context, []WebRTCInputEvent) error) error {
	var failures []error
	for {
		t.mu.Lock()
		if len(t.pending) == 0 || t.version == attempted || ctx.Err() != nil {
			if len(t.pending) > 0 && ctx.Err() != nil {
				failures = append(failures, ctx.Err())
			}
			t.gate <- struct{}{}
			t.mu.Unlock()
			return errors.Join(failures...)
		}
		t.mu.Unlock()
		var err error
		attempted, err = t.flush(ctx, release)
		if err != nil {
			failures = append(failures, err)
		}
	}
}

func runSharedWebRTCInputEvents(ctx context.Context, ch <-chan WebRTCInputEvent, display string, sess *WebRTCSession, registry *webRTCInputRegistry, inject func(context.Context, WebRTCInputEvent) error, release func(context.Context, []WebRTCInputEvent) error, resolvers ...webRTCInputResolver) {
	owner, err := registry.acquire(display, sess)
	if err != nil {
		logWebRTCInputFailure(sess, WebRTCInputEvent{Type: "acquire input"}, err)
		failWebRTCInputSession(sess, "input ownership unavailable")
		return
	}
	defer registry.release(display, owner)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), webRTCInputCleanupTimeout)
		defer cancel()
		if err := owner.retire(cleanupCtx, release); err != nil {
			logWebRTCInputFailure(sess, WebRTCInputEvent{Type: "release shared input"}, err)
		}
	}()
	// The shared owner performs final cleanup. The common reader still enforces
	// per-session bounds, ordering and explicit failure/overflow semantics.
	runWebRTCInputEventsWithRelease(ctx, ch, sess, func(inputCtx context.Context, event WebRTCInputEvent) error {
		return owner.inject(inputCtx, event, inject, release, resolvers...)
	}, func(context.Context, []WebRTCInputEvent) error { return nil })
}
