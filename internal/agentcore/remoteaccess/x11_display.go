package remoteaccess

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

var NewX11UtilityCommand = securityruntime.NewCommand

// Screens on one X server share core keyboard and pointer state. Keep the
// selected screen for capture/injection, but use the server for ownership.
func x11ServerIdentity(display string) string {
	display = NormalizeX11DisplayIdentifier(display)
	if display == "" {
		return ""
	}
	server, _, _ := strings.Cut(display[1:], ".")
	server = strings.TrimLeft(server, "0")
	if server == "" {
		server = "0"
	}
	return ":" + server
}

func PreferredX11Display() string {
	session := DetectDesktopSessionFn()
	if session.Type == DesktopSessionTypeX11 {
		if display := NormalizeX11DisplayIdentifier(session.Display); display != "" {
			return display
		}
	}

	if detected := AppendDetectedActiveDisplays(nil); len(detected) > 0 {
		return detected[0]
	}

	return ":0"
}

func WakeX11Display(display, xauthPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wakeX11Display(ctx, display, xauthPath)
}

func wakeX11Display(ctx context.Context, display, xauthPath string) {
	display = NormalizeX11DisplayIdentifier(display)
	if display == "" {
		return
	}

	if strings.TrimSpace(xauthPath) == "" {
		xauthPath = DiscoverDisplayXAuthorityFn(display)
	}

	run := func(name string, args ...string) {
		if ctx.Err() != nil {
			return
		}
		cmd, err := NewX11UtilityCommand(name, args...)
		if err != nil {
			if _, ok := err.(*exec.Error); ok {
				return
			}
			log.Printf("desktop: unable to prepare %s wake command for %s: %v", name, display, err)
			return
		}
		cmd.Env = BuildX11ClientEnv(display, xauthPath)
		if output, runErr := runX11WakeCommand(ctx, cmd); runErr != nil {
			log.Printf(
				"desktop: %s wake command failed for %s: %v (%s)",
				name,
				display,
				runErr,
				TruncateCommandOutput(output, 1024),
			)
		}
	}

	// Wake blanked/DPMS-suspended displays before attaching capture streams.
	run("xset", "-display", display, "dpms", "force", "on")
	run("xset", "-display", display, "s", "reset")

	// Nudge pointer state so locker/blanker stacks notice user activity.
	run("xdotool", "mousemove_relative", "--", "1", "0")
	run("xdotool", "mousemove_relative", "--", "-1", "0")
}

func runX11WakeCommand(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output := securityruntime.NewCappedRetainingWriter(64 * 1024)
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 500 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(finished)
		_ = cmd.Process.Kill()
	})
	err := cmd.Wait()
	if !stop() {
		<-finished
		err = errors.Join(ctx.Err(), err)
	}
	return output.Bytes(), err
}
