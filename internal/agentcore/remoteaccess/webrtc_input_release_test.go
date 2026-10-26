package remoteaccess

import (
	"context"
	"errors"
	"github.com/labtether/labtether-agent/internal/x11input"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestWebRTCInputCleanupBatchesHeldInputs(t *testing.T) {
	if last := os.Args[len(os.Args)-1]; last == "webrtc-release-helper" || last == "webrtc-stall-helper" {
		if last == "webrtc-stall-helper" {
			time.Sleep(2 * time.Second)
		}
		exitTestHelper(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		wayland, stallKeys bool
	}{
		{name: "X11"}, {name: "Wayland", wayland: true}, {name: "stalled keys", stallKeys: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := make([]WebRTCInputEvent, 0, 29)
			for letter := 'A'; letter <= 'Z'; letter++ {
				events = append(events, WebRTCInputEvent{Type: "keyup", Code: "Key" + string(letter), x11Keycode: uint8(30 + letter - 'A')})
			}
			for button := 0; button < 3; button++ {
				events = append(events, WebRTCInputEvent{Type: "mouseup", Button: button})
			}
			var sess *WebRTCSession
			if tc.wayland {
				sess = &WebRTCSession{sessionInfo: DesktopSessionInfo{Type: DesktopSessionTypeWayland}, inputBackend: "ydotool"}
			}
			calls := make(chan []string, 2)
			original := NewWebRTCSecurityCommand
			originalInternal := NewWebRTCInternalX11Command
			NewWebRTCInternalX11Command = func(args ...string) (*exec.Cmd, error) { return NewWebRTCSecurityCommand(x11input.PolicyName, args...) }
			NewWebRTCSecurityCommand = func(name string, args ...string) (*exec.Cmd, error) {
				calls <- append([]string{name}, args...)
				mode := "webrtc-release-helper"
				if tc.stallKeys && args[0] == "up" {
					mode = "webrtc-stall-helper"
				}
				return exec.Command(executable, "-test.run=^TestWebRTCInputCleanupBatchesHeldInputs$", "--", mode), nil
			}
			defer func() { NewWebRTCSecurityCommand = original; NewWebRTCInternalX11Command = originalInternal }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if tc.stallKeys {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			err := releaseWebRTCInputs(ctx, events, ":99", "", sess)
			if tc.stallKeys {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("stalled release error=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if len(calls) != 2 {
				t.Fatalf("release launched %d commands for 29 held inputs", len(calls))
			}
			for range 2 {
				args := <-calls
				expectedTool := "xdotool"
				if args[1] == "up" {
					expectedTool = x11input.PolicyName
				}
				if tc.wayland {
					expectedTool = "ydotool"
				}
				if args[0] != expectedTool {
					t.Fatalf("release backend=%q", args[0])
				}
				if args[1] == "up" || args[1] == "key" {
					offset := 2
					if tc.wayland {
						offset = 4
					}
					if len(args) != 26+offset || (tc.wayland && args[3] != "0") {
						t.Fatalf("keys missing from one zero-delay batch: %v", args)
					}
					for i, event := range events[:26] {
						expected, _ := x11RawKeyArgument(event)
						if tc.wayland {
							code, _ := DomCodeToLinuxInputCode(event.Code)
							expected = strconv.Itoa(code) + ":0"
						}
						if args[i+offset] != expected {
							t.Fatalf("release changed key mapping: %v", args)
						}
					}
				} else if tc.wayland {
					if len(args) != 7 || args[1] != "click" || args[3] != "0" || args[4] != "0x80" || args[5] != "0x82" || args[6] != "0x81" {
						t.Fatalf("button batch=%v", args)
					}
				} else {
					if len(args) != 7 || args[1] != "mouseup" || args[2] != "1" || args[3] != "mouseup" || args[4] != "2" || args[5] != "mouseup" || args[6] != "3" {
						t.Fatalf("button batch=%v", args)
					}
				}
			}
		})
	}
}
