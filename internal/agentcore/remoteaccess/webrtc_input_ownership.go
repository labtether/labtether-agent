package remoteaccess

import (
	"context"
	"strconv"
	"strings"
	"sync"
)

// Input state belongs to the latest session that pressed it on a specific
// desktop. Keep check, injection and release atomic so an old disconnect cannot
// release a key after a replacement controller has pressed it.
var webRTCInputOwners = struct {
	sync.Mutex
	owners map[string]*WebRTCSession
}{owners: make(map[string]*WebRTCSession)}

func webRTCInputOwnerKey(evt WebRTCInputEvent, display string, sess *WebRTCSession) string {
	if strings.TrimSpace(display) == "" {
		display = ":0"
	}
	if server := x11ServerIdentity(display); server != "" {
		display = server
	}
	scope := "x11:" + display
	wayland := sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland
	if wayland {
		scope = "wayland:" + sess.sessionInfo.XDGRuntimeDir + ":" + sess.sessionInfo.WaylandDisplay
	}
	switch strings.ToLower(strings.TrimSpace(evt.Type)) {
	case "keydown", "keyup":
		if wayland {
			if code, ok := DomCodeToLinuxInputCode(strings.TrimSpace(evt.Code)); ok {
				return scope + ":key:" + strconv.Itoa(code)
			}
		} else if key, ok := X11KeyArgument(evt); ok {
			return scope + ":key:" + key
		}
	case "mousedown", "mouseup":
		if evt.Button >= 0 && evt.Button <= 2 {
			return scope + ":button:" + strconv.Itoa(evt.Button)
		}
	}
	return ""
}

func injectOwnedWebRTCInput(ctx context.Context, evt WebRTCInputEvent, display, xauthPath string, sess *WebRTCSession) error {
	key := webRTCInputOwnerKey(evt, display, sess)
	if sess == nil || key == "" {
		return InjectSingleInput(evt, display, xauthPath, sess)
	}
	webRTCInputOwners.Lock()
	defer webRTCInputOwners.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	eventType := strings.ToLower(strings.TrimSpace(evt.Type))
	release := eventType == "keyup" || eventType == "mouseup"
	if release && webRTCInputOwners.owners[key] != sess {
		return nil
	}
	if !release {
		webRTCInputOwners.owners[key] = sess
	}
	err := InjectSingleInput(evt, display, xauthPath, sess)
	if release && err == nil {
		delete(webRTCInputOwners.owners, key)
	}
	return err
}
