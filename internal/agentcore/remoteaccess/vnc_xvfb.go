package remoteaccess

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// desktopShellTitle names the fallback shell window. Diagnostics find the
// shell by this title.
const desktopShellTitle = "LabTether desktop"

// The fallback display uses the 2.0 console's dark colours: the canvas behind
// the shell window, a sheet for the window and the main text colour.
const (
	desktopCanvasColor = "#0A0A0C"
	desktopSheetColor  = "#131316"
	desktopTextColor   = "#EDEDEF"
)

func StartDesktopBootstrapShell(display, xauthPath string) (*exec.Cmd, error) {
	display = strings.TrimSpace(display)
	if display == "" {
		return nil, nil
	}

	xtermPath, err := exec.LookPath("xterm")
	if err != nil {
		return nil, fmt.Errorf("xterm not found: install with 'apt install xterm'")
	}

	cmd, err := securityruntime.NewCommand(
		xtermPath,
		"-fa", "Monospace",
		"-fs", "11",
		"-geometry", "120x36+40+40",
		"-bg", desktopSheetColor,
		"-fg", desktopTextColor,
		"-title", desktopShellTitle,
		"-e", "sh", "-lc",
		`printf '\033]0;`+desktopShellTitle+`\007'; printf 'This machine has no desktop session, so LabTether started a virtual display (Xvfb) with this shell.\n'; printf 'Apps and desktops you start here show in Remote View.\n\n'; if [ -n "$SHELL" ] && [ -x "$SHELL" ]; then exec "$SHELL" -l; fi; if command -v bash >/dev/null 2>&1; then exec bash -l; fi; exec /bin/sh -l`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build xterm bootstrap command: %w", err)
	}
	cmd.Env = BuildX11ClientEnv(display, xauthPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xterm bootstrap: %w", err)
	}
	return cmd, nil
}

// SetXvfbFallbackBackground paints the Xvfb root window in the console's dark
// canvas colour, so the display is not plain black when no shell is open.
func SetXvfbFallbackBackground(display, xauthPath string) {
	xsetroot, err := exec.LookPath("xsetroot")
	if err != nil {
		return
	}
	cmd, cmdErr := securityruntime.NewCommand(xsetroot, "-solid", desktopCanvasColor, "-display", display)
	if cmdErr != nil {
		return
	}
	cmd.Env = BuildX11ClientEnv(display, xauthPath)
	_ = cmd.Run()
}

// buildXvfbArgs constructs arguments for launching Xvfb.
func BuildXvfbArgs(display, width, height int) []string {
	return []string{
		fmt.Sprintf(":%d", display),
		"-screen", "0",
		fmt.Sprintf("%dx%dx24", width, height),
	}
}

// startXvfb launches Xvfb on the given display number and returns the command
// and the path to the generated Xauthority file (empty if xauth is unavailable).
func StartXvfb(display, width, height int) (*exec.Cmd, string, error) {
	xvfbPath, err := exec.LookPath("Xvfb")
	if err != nil {
		return nil, "", fmt.Errorf("xvfb not found: install with 'apt install xvfb'")
	}

	// Best-effort: generate an Xauthority file for the display.
	// When xauth is unavailable, return "none" as a sentinel so downstream
	// callers (x11vnc) know to omit -auth rather than using -auth guess.
	xauthPath, xauthErr := CreateXauthorityFile(display)
	if xauthErr != nil {
		log.Printf("desktop: warning: could not create Xauthority for :%d: %v (proceeding without auth)", display, xauthErr)
		xauthPath = "none"
	}

	args := BuildXvfbArgs(display, width, height)
	if xauthPath != "" && xauthPath != "none" {
		args = append(args, "-auth", xauthPath)
	}

	cmd, err := securityruntime.NewCommand(xvfbPath, args...)
	if err != nil {
		RemoveProcessLog(xauthPath)
		return nil, "", fmt.Errorf("failed to build Xvfb command: %w", err)
	}
	if err := cmd.Start(); err != nil {
		RemoveProcessLog(xauthPath)
		return nil, "", fmt.Errorf("failed to start Xvfb: %w", err)
	}

	// Wait for Xvfb to create its lock file instead of a fixed sleep.
	if readyErr := WaitForXvfbReady(display, 5*time.Second); readyErr != nil {
		log.Printf("desktop: warning: Xvfb readiness probe failed for :%d: %v (continuing anyway)", display, readyErr)
	}
	return cmd, xauthPath, nil
}

// generateHexCookie returns a random hex string of n characters.
// Falls back to a timestamp-based value if crypto/rand fails.
func GenerateHexCookie(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use current UnixNano timestamp repeated to fill.
		ts := fmt.Sprintf("%x", time.Now().UnixNano())
		for len(ts) < n {
			ts += ts
		}
		return ts[:n]
	}
	return hex.EncodeToString(b)
}

// createXauthorityFile generates an Xauthority file for the given display
// using xauth. Returns the file path (caller is responsible for cleanup)
// or an error if xauth is not available.
func CreateXauthorityFile(displayNum int) (string, error) {
	xauthBin, err := exec.LookPath("xauth")
	if err != nil {
		return "", fmt.Errorf("xauth not found: %w", err)
	}

	f, err := os.CreateTemp("", fmt.Sprintf("labtether-xauth-%d-*.xauth", displayNum))
	if err != nil {
		return "", fmt.Errorf("failed to create Xauthority temp file: %w", err)
	}
	path := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		RemoveProcessLog(path)
		return "", fmt.Errorf("failed to prepare Xauthority file: %w", closeErr)
	}

	cookie := GenerateHexCookie(32)
	cmd, err := securityruntime.NewCommand(xauthBin, "-f", path, "add", fmt.Sprintf(":%d", displayNum), ".", cookie)
	if err != nil {
		RemoveProcessLog(path)
		return "", fmt.Errorf("failed to build xauth command: %w", err)
	}
	if output, runErr := securityruntime.CaptureCombinedOutput(cmd, securityruntime.DefaultCommandOutputLimit); runErr != nil {
		RemoveProcessLog(path)
		return "", fmt.Errorf("xauth add failed: %w (%s)", runErr, strings.TrimSpace(string(output)))
	}

	if chmodErr := os.Chmod(path, 0o600); chmodErr != nil { // #nosec G703 -- Path is a package-created Xauthority file.
		RemoveProcessLog(path)
		return "", fmt.Errorf("failed to secure Xauthority file permissions: %w", chmodErr)
	}
	return path, nil
}

// waitForXvfbReady polls for the Xvfb lock file to appear, indicating the
// server has initialized. Returns nil when found, or a timeout error.
func WaitForXvfbReady(display int, timeout time.Duration) error {
	lockFile := fmt.Sprintf("/tmp/.X%d-lock", display)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(lockFile); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for Xvfb lock file %s", lockFile)
}
