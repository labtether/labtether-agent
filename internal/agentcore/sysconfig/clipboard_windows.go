//go:build windows

package sysconfig

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

var windowsClipboardCurrentSessionID = currentWindowsClipboardSessionID

func currentWindowsClipboardSessionID() (uint32, error) {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &sessionID); err != nil {
		return 0, err
	}
	return sessionID, nil
}

func requireInteractiveWindowsClipboardSession() error {
	sessionID, err := windowsClipboardCurrentSessionID()
	if err != nil {
		return fmt.Errorf("determine Windows clipboard session: %w", err)
	}
	if sessionID == 0 {
		return fmt.Errorf("Windows clipboard is unavailable from service session 0; an interactive-session agent helper is required")
	}
	return nil
}

// PlatformClipboardRead reads the Windows clipboard using PowerShell Get-Clipboard.
func PlatformClipboardRead(format string) (text string, imgBase64 string, err error) {
	if err := requireInteractiveWindowsClipboardSession(); err != nil {
		return "", "", err
	}
	if format == "image" || format == "image/png" {
		return "", "", fmt.Errorf("image clipboard read not yet supported on Windows")
	}

	out, err := clipboardCommandOutput(nil, "powershell", "-NoProfile", "-NonInteractive", "-STA", "-Command", windowsClipboardReadTextScript)
	if err != nil {
		return "", "", fmt.Errorf("Get-Clipboard failed: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		return "", "", fmt.Errorf("invalid clipboard text encoding: %w", err)
	}
	return string(decoded), "", nil
}

// PlatformClipboardWriteText writes text to the Windows clipboard using PowerShell Set-Clipboard.
func PlatformClipboardWriteText(text string) error {
	if err := requireInteractiveWindowsClipboardSession(); err != nil {
		return err
	}
	// Send ASCII base64 on stdin so PowerShell cannot split lines or change Unicode.
	cmd, err := ClipboardNewCommand("powershell", "-NoProfile", "-NonInteractive", "-STA", "-Command", windowsClipboardWriteTextScript)
	if err != nil {
		return fmt.Errorf("failed to create PowerShell command: %w", err)
	}
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString([]byte(text)))
	if err := runClipboardCommand(cmd, clipboardCommandTimeout); err != nil {
		return fmt.Errorf("Set-Clipboard failed: %w", err)
	}
	return nil
}

// PlatformClipboardWriteImage writes an image to the Windows clipboard.
// Not yet supported — returns an error.
func PlatformClipboardWriteImage(base64Data string) error {
	if err := requireInteractiveWindowsClipboardSession(); err != nil {
		return err
	}
	return fmt.Errorf("image clipboard write not yet supported on Windows")
}
