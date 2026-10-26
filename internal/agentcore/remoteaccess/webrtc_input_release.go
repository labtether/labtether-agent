package remoteaccess

import (
	"context"
	"errors"
	"fmt"
	"github.com/labtether/labtether-agent/internal/x11input"
	"strconv"
	"strings"
	"sync"
)

// Release keys and buttons in at most two helpers. Run both groups together so
// a stalled key backend cannot consume the button group's whole cleanup budget.
// Delay zero avoids spending the cleanup budget on artificial per-key pauses.
func releaseWebRTCInputs(ctx context.Context, events []WebRTCInputEvent, display, xauthPath string, sess *WebRTCSession) error {
	name := "xdotool"
	if strings.TrimSpace(display) == "" {
		display = ":0"
	}
	env := BuildX11ClientEnv(display, xauthPath)
	keyName := x11input.PolicyName
	keys := []string{"up"}
	var buttons []string
	wayland := sess != nil && sess.sessionInfo.Type == DesktopSessionTypeWayland
	if wayland {
		if backend := ResolveWaylandInputBackend(sess.inputBackend); backend != "ydotool" {
			return fmt.Errorf("Wayland input backend %q is unavailable", backend)
		}
		name = "ydotool"
		keyName = name
		env = BuildWaylandPipeWireEnv(sess.sessionInfo)
		keys = []string{"key", "--key-delay", "0"}
		buttons = []string{"click", "--next-delay", "0"}
	}
	keyCount, buttonCount := 0, 0
	for _, event := range events {
		switch event.Type {
		case "keyup":
			if wayland {
				if code, ok := DomCodeToLinuxInputCode(strings.TrimSpace(event.Code)); ok {
					keys = append(keys, strconv.Itoa(code)+":0")
					keyCount++
				}
			} else {
				key, err := x11RawKeyArgument(event)
				if err != nil {
					return err
				}
				keys = append(keys, key)
				keyCount++
			}
		case "mouseup":
			if wayland {
				if button, ok := BrowserButtonToYdotoolButtonState(event.Button, false); ok {
					buttons = append(buttons, button)
					buttonCount++
				}
			} else {
				buttons = append(buttons, "mouseup", strconv.Itoa(event.Button+1))
				buttonCount++
			}
		}
	}
	type call struct {
		name string
		args []string
	}
	var calls []call
	if keyCount > 0 {
		calls = append(calls, call{keyName, keys})
	}
	if buttonCount > 0 {
		calls = append(calls, call{name, buttons})
	}
	results := make(chan error, len(calls))
	var workers sync.WaitGroup
	for _, command := range calls {
		workers.Add(1)
		go func(command call) {
			defer workers.Done()
			results <- runWebRTCInputCommandContext(ctx, command.name, env, command.args...)
		}(command)
	}
	workers.Wait()
	close(results)
	var failures []error
	for err := range results {
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
