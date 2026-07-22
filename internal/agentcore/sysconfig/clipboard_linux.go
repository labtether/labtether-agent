//go:build linux

package sysconfig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const linuxClipboardImageMaxBytes = 8 * 1024 * 1024

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// LinuxDesktopSessionInfo holds the minimal desktop session info needed by
// clipboard operations. The parent package maps its full session info into this.
type LinuxDesktopSessionInfo struct {
	Type           string
	Display        string
	WaylandDisplay string
	XDGRuntimeDir  string
}

// Injectable function variables for desktop session detection.
// The parent agentcore package wires these at init time.
var (
	DetectLinuxDesktopSessionFn    func() LinuxDesktopSessionInfo
	AppendDetectedActiveDisplaysFn func(dst []string) []string
)

var ClipboardLookPath = exec.LookPath
var ClipboardNewCommand = securityruntime.NewCommand

func buildLinuxClipboardEnv() []string {
	return buildLinuxClipboardEnvForSession(detectLinuxClipboardSession())
}

func detectLinuxClipboardSession() LinuxDesktopSessionInfo {
	if DetectLinuxDesktopSessionFn != nil {
		return DetectLinuxDesktopSessionFn()
	}
	return LinuxDesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":0"}
}

func buildLinuxClipboardEnvForSession(session LinuxDesktopSessionInfo) []string {
	if session.Type == DesktopSessionTypeWayland {
		env := securityruntime.SanitizedChildEnv()
		filtered := make([]string, 0, len(env)+2)
		for _, entry := range env {
			if strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") ||
				strings.HasPrefix(entry, "WAYLAND_DISPLAY=") ||
				strings.HasPrefix(entry, "DISPLAY=") ||
				strings.HasPrefix(entry, "XAUTHORITY=") {
				continue
			}
			filtered = append(filtered, entry)
		}
		if runtimeDir := strings.TrimSpace(session.XDGRuntimeDir); runtimeDir != "" {
			filtered = append(filtered, "XDG_RUNTIME_DIR="+runtimeDir)
		}
		if waylandDisplay := strings.TrimSpace(session.WaylandDisplay); waylandDisplay != "" {
			filtered = append(filtered, "WAYLAND_DISPLAY="+waylandDisplay)
		}
		return filtered
	}

	display := session.Display
	if display == "" {
		if AppendDetectedActiveDisplaysFn != nil {
			if detected := AppendDetectedActiveDisplaysFn(nil); len(detected) > 0 {
				display = detected[0]
			}
		}
	}
	if display == "" {
		display = ":0"
	}
	return buildX11ClipboardEnv(display, "")
}

func buildX11ClipboardEnv(display, xauthPath string) []string {
	if BuildX11ClientEnvFn != nil {
		return BuildX11ClientEnvFn(display, xauthPath)
	}
	// Fallback: minimal X11 env
	env := securityruntime.SanitizedChildEnv()
	result := make([]string, 0, len(env)+2)
	for _, entry := range env {
		if strings.HasPrefix(entry, "DISPLAY=") || strings.HasPrefix(entry, "XAUTHORITY=") {
			continue
		}
		result = append(result, entry)
	}
	result = append(result, "DISPLAY="+display)
	if xauthPath != "" {
		result = append(result, "XAUTHORITY="+xauthPath)
	}
	return result
}

func clipboardCommandOutput(env []string, name string, args ...string) ([]byte, error) {
	cmd, err := ClipboardNewCommand(name, args...)
	if err != nil {
		return nil, err
	}
	cmd.Env = env
	return securityruntime.CaptureOutput(cmd, securityruntime.DefaultCommandOutputLimit)
}

// PlatformClipboardRead reads the Linux clipboard using the native session tool.
func PlatformClipboardRead(format string) (text string, imgBase64 string, err error) {
	wantsImage := format == "image" || format == "image/png"
	session := detectLinuxClipboardSession()
	env := buildLinuxClipboardEnvForSession(session)
	if session.Type == DesktopSessionTypeWayland {
		if _, lookErr := ClipboardLookPath("wl-paste"); lookErr != nil {
			return "", "", fmt.Errorf("Wayland clipboard read requires wl-paste to be installed")
		}
		args := []string{"--no-newline"}
		if wantsImage {
			args = []string{"--type", "image/png"}
		}
		out, readErr := clipboardCommandOutput(env, "wl-paste", args...)
		if readErr != nil {
			return "", "", fmt.Errorf("wl-paste failed: %w", readErr)
		}
		if wantsImage {
			return "", base64.StdEncoding.EncodeToString(out), nil
		}
		return string(out), "", nil
	}

	// Try xclip first, fall back to xsel.
	if _, lookErr := ClipboardLookPath("xclip"); lookErr == nil {
		args := []string{"-selection", "clipboard", "-o"}
		if wantsImage {
			args = []string{"-selection", "clipboard", "-t", "image/png", "-o"}
		}
		out, err := clipboardCommandOutput(env, "xclip", args...)
		if err != nil {
			return "", "", fmt.Errorf("xclip failed: %w", err)
		}
		if wantsImage {
			return "", base64.StdEncoding.EncodeToString(out), nil
		}
		return strings.TrimRight(string(out), "\n"), "", nil
	}
	if wantsImage {
		return "", "", fmt.Errorf("image clipboard read requires xclip to be installed")
	}

	if _, lookErr := ClipboardLookPath("xsel"); lookErr == nil {
		out, err := clipboardCommandOutput(env, "xsel", "--clipboard", "--output")
		if err != nil {
			return "", "", fmt.Errorf("xsel failed: %w", err)
		}
		return strings.TrimRight(string(out), "\n"), "", nil
	}

	return "", "", fmt.Errorf("clipboard read requires xclip or xsel to be installed")
}

// PlatformClipboardWriteText writes text using the native session clipboard tool.
func PlatformClipboardWriteText(text string) error {
	session := detectLinuxClipboardSession()
	env := buildLinuxClipboardEnvForSession(session)
	if session.Type == DesktopSessionTypeWayland {
		if _, lookErr := ClipboardLookPath("wl-copy"); lookErr != nil {
			return fmt.Errorf("Wayland clipboard write requires wl-copy to be installed")
		}
		cmd, err := ClipboardNewCommand("wl-copy")
		if err != nil {
			return fmt.Errorf("failed to create wl-copy command: %w", err)
		}
		cmd.Env = env
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("wl-copy failed: %w", err)
		}
		return nil
	}

	// Try xclip first, fall back to xsel.
	if _, lookErr := ClipboardLookPath("xclip"); lookErr == nil {
		cmd, err := ClipboardNewCommand("xclip", "-selection", "clipboard")
		if err != nil {
			return fmt.Errorf("failed to create xclip command: %w", err)
		}
		cmd.Env = env
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("xclip failed: %w", err)
		}
		return nil
	}

	if _, lookErr := ClipboardLookPath("xsel"); lookErr == nil {
		cmd, err := ClipboardNewCommand("xsel", "--clipboard", "--input")
		if err != nil {
			return fmt.Errorf("failed to create xsel command: %w", err)
		}
		cmd.Env = env
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("xsel failed: %w", err)
		}
		return nil
	}

	return fmt.Errorf("clipboard write requires xclip or xsel to be installed")
}

// PlatformClipboardWriteImage writes a bounded PNG image to the Linux clipboard.
func PlatformClipboardWriteImage(base64Data string) error {
	if len(base64Data) > base64.StdEncoding.EncodedLen(linuxClipboardImageMaxBytes) {
		return fmt.Errorf("clipboard image exceeds %d bytes", linuxClipboardImageMaxBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Data))
	if err != nil {
		return fmt.Errorf("invalid clipboard image encoding")
	}
	if len(decoded) > linuxClipboardImageMaxBytes {
		return fmt.Errorf("clipboard image exceeds %d bytes", linuxClipboardImageMaxBytes)
	}
	if !bytes.HasPrefix(decoded, pngSignature) {
		return fmt.Errorf("clipboard image is not a PNG")
	}
	session := detectLinuxClipboardSession()
	env := buildLinuxClipboardEnvForSession(session)
	if session.Type == DesktopSessionTypeWayland {
		if _, lookErr := ClipboardLookPath("wl-copy"); lookErr != nil {
			return fmt.Errorf("Wayland image clipboard write requires wl-copy to be installed")
		}
		cmd, commandErr := ClipboardNewCommand("wl-copy", "--type", "image/png")
		if commandErr != nil {
			return fmt.Errorf("failed to create wl-copy command: %w", commandErr)
		}
		cmd.Env = env
		cmd.Stdin = bytes.NewReader(decoded)
		if runErr := cmd.Run(); runErr != nil {
			return fmt.Errorf("wl-copy failed: %w", runErr)
		}
		return nil
	}

	if _, lookErr := ClipboardLookPath("xclip"); lookErr != nil {
		return fmt.Errorf("image clipboard write requires xclip to be installed")
	}
	cmd, commandErr := ClipboardNewCommand("xclip", "-selection", "clipboard", "-t", "image/png")
	if commandErr != nil {
		return fmt.Errorf("failed to create xclip command: %w", commandErr)
	}
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(decoded)
	if runErr := cmd.Run(); runErr != nil {
		return fmt.Errorf("xclip failed: %w", runErr)
	}
	return nil
}
