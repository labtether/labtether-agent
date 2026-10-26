package remoteaccess

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"
)

const maxHeldWebRTCInputs = 256
const webRTCInputCleanupTimeout = 2 * time.Second

// InjectInputEvents owns pressed state for one session. Its final release uses
// a fresh context because the normal session context is already canceled.
func InjectInputEvents(ctx context.Context, ch <-chan WebRTCInputEvent, display, xauthPath string, sess *WebRTCSession) {
	inject := func(inputCtx context.Context, evt WebRTCInputEvent) error {
		return injectSingleInputContext(inputCtx, evt, display, xauthPath, sess)
	}
	resolve := func(inputCtx context.Context, event WebRTCInputEvent) (WebRTCInputEvent, error) {
		if sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland {
			return event, nil
		}
		return resolveWebRTCX11Input(inputCtx, event, display, xauthPath)
	}
	runSharedWebRTCInputEvents(ctx, ch, display, sess, &sharedWebRTCInputTargets, inject, func(cleanupCtx context.Context, releases []WebRTCInputEvent) error {
		return releaseWebRTCInputs(cleanupCtx, releases, display, xauthPath, sess)
	}, resolve)
}

func runWebRTCInputEvents(ctx context.Context, ch <-chan WebRTCInputEvent, sess *WebRTCSession, inject func(context.Context, WebRTCInputEvent) error) {
	runWebRTCInputEventsWithRelease(ctx, ch, sess, inject, func(cleanupCtx context.Context, releases []WebRTCInputEvent) error {
		for _, release := range releases {
			if err := inject(cleanupCtx, release); err != nil {
				return err
			}
		}
		return nil
	})
}

func runWebRTCInputEventsWithRelease(ctx context.Context, ch <-chan WebRTCInputEvent, sess *WebRTCSession, inject func(context.Context, WebRTCInputEvent) error, release func(context.Context, []WebRTCInputEvent) error) {
	held := make(map[string]WebRTCInputEvent)
	defer func() {
		if len(held) == 0 {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), webRTCInputCleanupTimeout)
		defer cancel()
		releases := make([]WebRTCInputEvent, 0, len(held))
		for _, event := range held {
			releases = append(releases, event)
		}
		if err := release(cleanupCtx, releases); err != nil {
			logWebRTCInputFailure(sess, WebRTCInputEvent{Type: "release held input"}, err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok || ctx.Err() != nil {
				return
			}
			evt.Type = strings.TrimSpace(strings.ToLower(evt.Type))
			key := webRTCHeldInputKey(evt, sess)
			if key != "" && (evt.Type == "keydown" || evt.Type == "mousedown") {
				if _, exists := held[key]; !exists && len(held) >= maxHeldWebRTCInputs {
					failWebRTCInputSession(sess, "too many held inputs")
					return
				}
				release := evt
				if evt.Type == "keydown" {
					release.Type = "keyup"
				} else {
					release.Type = "mouseup"
				}
				// A failed/canceled helper may already have pressed the key.
				// Retain the release until a matching up command succeeds.
				held[key] = release
			}
			if err := inject(ctx, evt); err != nil {
				logWebRTCInputFailure(sess, evt, err)
				if ctx.Err() == nil {
					failWebRTCInputSession(sess, "input injection failed")
				}
				return
			}
			if evt.Type == "keyup" || evt.Type == "mouseup" {
				delete(held, key)
			}
		}
	}
}

func webRTCHeldInputKey(evt WebRTCInputEvent, sess *WebRTCSession) string {
	switch evt.Type {
	case "mousedown", "mouseup":
		return "button:" + strconv.Itoa(evt.Button)
	case "keydown", "keyup":
		if evt.x11Keycode != 0 {
			return "x11-keycode:" + strconv.Itoa(int(evt.x11Keycode))
		}
		if sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland {
			if code, ok := DomCodeToLinuxInputCode(strings.TrimSpace(evt.Code)); ok {
				return "key:" + strconv.Itoa(code)
			}
		} else if key, ok := X11KeyArgument(evt); ok {
			return "key:" + key
		}
	}
	return ""
}

func failWebRTCInputSession(sess *WebRTCSession, reason string) {
	if sess != nil && sess.onInputFailure != nil {
		sess.onInputFailure(reason)
	}
}

func logWebRTCInputFailure(sess *WebRTCSession, evt WebRTCInputEvent, err error) {
	sessionID, backend := "", DesktopBackendX11
	if sess != nil {
		sessionID = strings.TrimSpace(sess.sessionID)
		backend = strings.TrimSpace(sess.desktopBackend)
	}
	log.Printf("webrtc: input injection failed session=%s backend=%s event=%s: %v",
		ValueOrDash(sessionID), ValueOrDash(backend), ValueOrDash(evt.Type), err)
}

func (wm *WebRTCManager) enqueueWebRTCInput(transport MessageSender, sess *WebRTCSession, evt WebRTCInputEvent) {
	wm.Mu.Lock()
	if wm.Sessions[sess.sessionID] != sess {
		wm.Mu.Unlock()
		return
	}
	select {
	case <-sess.done:
		wm.Mu.Unlock()
		return
	default:
	}
	select {
	case sess.inputCh <- evt:
		wm.Mu.Unlock()
		return
	default:
		wm.Mu.Unlock()
		wm.failWebRTCInput(transport, sess, "input queue full; session closed")
	}
}

func (wm *WebRTCManager) failWebRTCInput(transport MessageSender, sess *WebRTCSession, reason string) {
	sess.inputFailureOnce.Do(func() {
		if sess.cancel != nil {
			sess.cancel()
		}
		// Pion close and the Hub write can wait on I/O. Keep both off the socket
		// reader and data-channel callback. At most one failure task per session.
		go func() {
			if wm.cleanupSessionInstance(sess.sessionID, sess, reason) {
				if transport != nil {
					SendWebRTCStopped(transport, sess.sessionID, reason)
				}
			} else {
				sess.close(reason)
			}
		}()
	})
}
