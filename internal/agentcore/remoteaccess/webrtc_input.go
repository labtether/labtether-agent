package remoteaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
	"log"
	"strconv"
	"strings"
)

type WebRTCInputEvent struct {
	Type    string `json:"type"`
	KeyCode int    `json:"keyCode,omitempty"`
	Code    string `json:"code,omitempty"`
	Key     string `json:"key,omitempty"`
	X       int    `json:"x,omitempty"`
	Y       int    `json:"y,omitempty"`
	Button  int    `json:"button,omitempty"`
	DeltaY  int    `json:"deltaY,omitempty"`
}

func InjectInputEvents(ctx context.Context, ch <-chan WebRTCInputEvent, display, xauthPath string, sess *WebRTCSession) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			if err := InjectSingleInput(evt, display, xauthPath, sess); err != nil {
				sessionID := ""
				backend := DesktopBackendX11
				if sess != nil {
					sessionID = strings.TrimSpace(sess.sessionID)
					backend = strings.TrimSpace(sess.desktopBackend)
				}
				log.Printf(
					"webrtc: input injection failed session=%s backend=%s event=%s: %v",
					ValueOrDash(sessionID),
					ValueOrDash(backend),
					ValueOrDash(strings.TrimSpace(strings.ToLower(evt.Type))),
					err,
				)
			}
		}
	}
}

func BuildWaylandPipeWireEnv(session DesktopSessionInfo) []string {
	env := securityruntime.SanitizedChildEnv()
	filtered := make([]string, 0, len(env)+2)
	for _, e := range env {
		if strings.HasPrefix(e, "XDG_RUNTIME_DIR=") ||
			strings.HasPrefix(e, "WAYLAND_DISPLAY=") ||
			strings.HasPrefix(e, "DISPLAY=") ||
			strings.HasPrefix(e, "XAUTHORITY=") {
			continue
		}
		filtered = append(filtered, e)
	}
	if runtimeDir := strings.TrimSpace(session.XDGRuntimeDir); runtimeDir != "" {
		filtered = append(filtered, "XDG_RUNTIME_DIR="+runtimeDir)
	}
	if waylandDisplay := strings.TrimSpace(session.WaylandDisplay); waylandDisplay != "" {
		filtered = append(filtered, "WAYLAND_DISPLAY="+waylandDisplay)
	}
	return filtered
}

func InjectSingleInput(evt WebRTCInputEvent, display, xauthPath string, sess *WebRTCSession) error {
	eventType := strings.TrimSpace(strings.ToLower(evt.Type))
	if eventType == "" {
		return fmt.Errorf("input event type is required")
	}
	if sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland {
		return InjectWaylandInputEvent(evt, sess)
	}
	if strings.TrimSpace(display) == "" {
		display = ":0"
	}

	run := func(args ...string) error {
		return RunWebRTCInputCommand("xdotool", BuildX11ClientEnv(display, xauthPath), args...)
	}

	switch eventType {
	case "keydown":
		if keyArg, ok := X11KeyArgument(evt); ok {
			return run("keydown", keyArg)
		}
		return fmt.Errorf("unsupported X11 keydown event")
	case "keyup":
		if keyArg, ok := X11KeyArgument(evt); ok {
			return run("keyup", keyArg)
		}
		return fmt.Errorf("unsupported X11 keyup event")
	case "mousemove":
		return run("mousemove", "--screen", "0", strconv.Itoa(evt.X), strconv.Itoa(evt.Y))
	case "mousedown":
		return run("mousedown", strconv.Itoa(evt.Button+1))
	case "mouseup":
		return run("mouseup", strconv.Itoa(evt.Button+1))
	case "scroll":
		if evt.DeltaY < 0 {
			return run("click", "4")
		} else if evt.DeltaY > 0 {
			return run("click", "5")
		}
		return nil
	default:
		return fmt.Errorf("unsupported X11 input event type %q", eventType)
	}
}

// RunWebRTCInputCommand executes one validated input command and preserves a
// bounded diagnostic on failure so input loss is observable without logging
// the full event payload.
func RunWebRTCInputCommand(name string, env []string, args ...string) error {
	cmd, err := NewWebRTCSecurityCommand(name, args...)
	if err != nil {
		return fmt.Errorf("build %s input command: %w", name, err)
	}
	cmd.Env = env
	out, runErr := securityruntime.CaptureCombinedOutput(cmd, securityruntime.DefaultCommandOutputLimit)
	if runErr == nil {
		return nil
	}
	detail := TruncateCommandOutput(out, 1024)
	if detail != "" {
		return fmt.Errorf("run %s input command: %w: %s", name, runErr, detail)
	}
	return fmt.Errorf("run %s input command: %w", name, runErr)
}

func X11KeyArgument(evt WebRTCInputEvent) (string, bool) {
	if keysym, ok := DomCodeToX11Keysym(strings.TrimSpace(evt.Code)); ok {
		return keysym, true
	}
	if keysym, ok := DomKeyToX11Keysym(strings.TrimSpace(evt.Key)); ok {
		return keysym, true
	}
	if evt.KeyCode > 0 {
		return fmt.Sprintf("0x%x", evt.KeyCode), true
	}
	return "", false
}

func InjectWaylandInputEvent(evt WebRTCInputEvent, sess *WebRTCSession) error {
	if sess == nil {
		return fmt.Errorf("Wayland input session is required")
	}
	backend := ResolveWaylandInputBackend(sess.inputBackend)
	if backend != "ydotool" {
		return fmt.Errorf("Wayland input backend %q is unavailable", backend)
	}

	run := func(args ...string) error {
		return RunWebRTCInputCommand("ydotool", BuildWaylandPipeWireEnv(sess.sessionInfo), args...)
	}

	switch strings.TrimSpace(strings.ToLower(evt.Type)) {
	case "keydown", "keyup":
		code, ok := DomCodeToLinuxInputCode(strings.TrimSpace(evt.Code))
		if !ok {
			return fmt.Errorf("unsupported Wayland key code %q", strings.TrimSpace(evt.Code))
		}
		state := "0"
		if strings.EqualFold(strings.TrimSpace(evt.Type), "keydown") {
			state = "1"
		}
		return run("key", fmt.Sprintf("%d:%s", code, state))
	case "mousemove":
		return run("mousemove", "--absolute", "-x", strconv.Itoa(evt.X), "-y", strconv.Itoa(evt.Y))
	case "mousedown":
		if buttonCode, ok := BrowserButtonToYdotoolButtonState(evt.Button, true); ok {
			return run("click", buttonCode)
		}
		return fmt.Errorf("unsupported Wayland mouse button %d", evt.Button)
	case "mouseup":
		if buttonCode, ok := BrowserButtonToYdotoolButtonState(evt.Button, false); ok {
			return run("click", buttonCode)
		}
		return fmt.Errorf("unsupported Wayland mouse button %d", evt.Button)
	case "scroll":
		if evt.DeltaY < 0 {
			return run("mousemove", "--wheel", "-x", "0", "-y", "1")
		} else if evt.DeltaY > 0 {
			return run("mousemove", "--wheel", "-x", "0", "-y", "-1")
		}
		return nil
	default:
		return fmt.Errorf("unsupported Wayland input event type %q", strings.TrimSpace(strings.ToLower(evt.Type)))
	}
}

func ResolveWaylandInputBackend(configured string) string {
	switch strings.TrimSpace(strings.ToLower(configured)) {
	case "none":
		return "none"
	case "ydotool":
		return "ydotool"
	case "auto", "":
		if _, err := WebRTCLookPath("ydotool"); err == nil {
			return "ydotool"
		}
	}
	return "none"
}

func BrowserButtonToYdotoolButton(button int) (string, bool) {
	base, ok := browserButtonToYdotoolBase(button)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("0x%X", 0xC0|base), true
}

// BrowserButtonToYdotoolButtonState maps browser button identifiers to the
// ydotool click bitmask. 0x40 emits button-down only and 0x80 emits button-up
// only, preserving drag state across separate WebRTC events.
func BrowserButtonToYdotoolButtonState(button int, pressed bool) (string, bool) {
	base, ok := browserButtonToYdotoolBase(button)
	if !ok {
		return "", false
	}
	mask := 0x80
	if pressed {
		mask = 0x40
	}
	return fmt.Sprintf("0x%X", mask|base), true
}

func browserButtonToYdotoolBase(button int) (int, bool) {
	switch button {
	case 0:
		return 0, true
	case 1:
		return 2, true
	case 2:
		return 1, true
	default:
		return 0, false
	}
}

func DecodeWebRTCInputEvent(raw []byte) (WebRTCInputEvent, error) {
	var evt WebRTCInputEvent
	var fallback protocol.WebRTCInputData

	directErr := json.Unmarshal(raw, &evt)
	fallbackErr := json.Unmarshal(raw, &fallback)
	if directErr != nil && fallbackErr != nil {
		return WebRTCInputEvent{}, directErr
	}

	if strings.TrimSpace(evt.Type) == "" && strings.TrimSpace(fallback.Type) == "" {
		return WebRTCInputEvent{}, fmt.Errorf("missing type")
	}

	if strings.TrimSpace(evt.Type) == "" {
		evt.Type = fallback.Type
	}
	if evt.KeyCode == 0 && fallback.KeyCode != 0 {
		evt.KeyCode = fallback.KeyCode
	}
	if strings.TrimSpace(evt.Code) == "" && strings.TrimSpace(fallback.Code) != "" {
		evt.Code = fallback.Code
	}
	if strings.TrimSpace(evt.Key) == "" && strings.TrimSpace(fallback.Key) != "" {
		evt.Key = fallback.Key
	}
	if evt.X == 0 && fallback.X != 0 {
		evt.X = fallback.X
	}
	if evt.Y == 0 && fallback.Y != 0 {
		evt.Y = fallback.Y
	}
	if evt.Button == 0 && fallback.Button != 0 {
		evt.Button = fallback.Button
	}
	if evt.DeltaY == 0 && fallback.DeltaY != 0 {
		evt.DeltaY = fallback.DeltaY
	}
	return evt, nil
}
