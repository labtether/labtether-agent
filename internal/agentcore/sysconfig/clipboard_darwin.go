//go:build darwin

package sysconfig

import (
	"fmt"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// PlatformClipboardRead reads the macOS clipboard using pbpaste.
func PlatformClipboardRead(format string) (text string, imgBase64 string, err error) {
	if format == "image" || format == "image/png" {
		return "", "", fmt.Errorf("image clipboard read not yet supported on macOS")
	}

	out, err := clipboardCommandOutput(darwinClipboardEnv(), "pbpaste")
	if err != nil {
		return "", "", fmt.Errorf("pbpaste failed: %w", err)
	}
	return string(out), "", nil
}

// PlatformClipboardWriteText writes text to the macOS clipboard using pbcopy.
func PlatformClipboardWriteText(text string) error {
	cmd, err := ClipboardNewCommand("pbcopy")
	if err != nil {
		return fmt.Errorf("failed to create pbcopy command: %w", err)
	}
	cmd.Stdin = strings.NewReader(text)
	cmd.Env = darwinClipboardEnv()
	if err := runClipboardCommand(cmd, clipboardCommandTimeout); err != nil {
		return fmt.Errorf("pbcopy failed: %w", err)
	}
	return nil
}

// Launch agents need not inherit a Terminal locale. pbcopy/pbpaste otherwise
// decode and encode with that ambient locale, although the wire text is UTF-8.
func darwinClipboardEnv() []string {
	env := securityruntime.SanitizedChildEnv()
	filtered := make([]string, 0, len(env)+3)
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key != "LANG" && key != "LC_ALL" && key != "LC_CTYPE" {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8", "LC_CTYPE=en_US.UTF-8")
}

// PlatformClipboardWriteImage writes an image to the macOS clipboard.
// Not yet supported — returns an error.
func PlatformClipboardWriteImage(base64Data string) error {
	return fmt.Errorf("image clipboard write not yet supported on macOS")
}
