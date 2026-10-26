package remoteaccess

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Motion may be superseded, but dropping a key/button release leaves remote
// input stuck. Apply bounded backpressure to state changes and tear down a
// stalled session so its injector can release only the input it owns.
func (s *WebRTCSession) queueInputEvent(evt WebRTCInputEvent) bool {
	select {
	case <-s.done:
		return false
	default:
	}
	if strings.EqualFold(strings.TrimSpace(evt.Type), "mousemove") {
		select {
		case s.inputCh <- evt:
		case <-s.done:
			return false
		default:
		}
		return true
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case s.inputCh <- evt:
		return true
	case <-s.done:
		return false
	case <-timer.C:
		s.close("input queue stalled")
		return false
	}
}

type webRTCPressedInput struct {
	keys    map[string]WebRTCInputEvent
	buttons map[int]bool
}

func (pressed *webRTCPressedInput) observe(evt WebRTCInputEvent) {
	if pressed.keys == nil {
		pressed.keys = make(map[string]WebRTCInputEvent)
	}
	if pressed.buttons == nil {
		pressed.buttons = make(map[int]bool)
	}
	identity := evt.Code
	if identity == "" {
		identity = evt.Key
	}
	if identity == "" {
		identity = strconv.Itoa(evt.KeyCode)
	}
	switch strings.ToLower(strings.TrimSpace(evt.Type)) {
	case "keydown":
		pressed.keys[identity] = evt
	case "keyup":
		delete(pressed.keys, identity)
	case "mousedown":
		if evt.Button >= 0 && evt.Button <= 2 {
			pressed.buttons[evt.Button] = true
		}
	case "mouseup":
		delete(pressed.buttons, evt.Button)
	}
}

func (pressed *webRTCPressedInput) release(display, xauthPath string, sess *WebRTCSession) {
	webRTCInputOwners.Lock()
	defer webRTCInputOwners.Unlock()
	wayland := sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland
	args := []string{"keyup"}
	if wayland {
		args[0] = "key"
	}
	for _, evt := range pressed.keys {
		key := webRTCInputOwnerKey(evt, display, sess)
		if sess != nil && webRTCInputOwners.owners[key] != sess {
			continue
		}
		delete(webRTCInputOwners.owners, key)
		if wayland {
			if code, ok := DomCodeToLinuxInputCode(strings.TrimSpace(evt.Code)); ok {
				args = append(args, fmt.Sprintf("%d:0", code))
			}
		} else if key, ok := X11KeyArgument(evt); ok {
			args = append(args, key)
		}
	}
	if len(args) > 1 {
		if wayland {
			_ = RunWebRTCInputCommand("ydotool", BuildWaylandPipeWireEnv(sess.sessionInfo), args...)
		} else {
			_ = RunWebRTCInputCommand("xdotool", BuildX11ClientEnv(display, xauthPath), args...)
		}
	}
	for button := range pressed.buttons {
		evt := WebRTCInputEvent{Type: "mouseup", Button: button}
		key := webRTCInputOwnerKey(evt, display, sess)
		if sess != nil && webRTCInputOwners.owners[key] != sess {
			continue
		}
		delete(webRTCInputOwners.owners, key)
		_ = InjectSingleInput(evt, display, xauthPath, sess)
	}
}
