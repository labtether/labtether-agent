package remoteaccess

import (
	"fmt"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// startMacVNC checks for macOS Screen Sharing VNC or returns an error.
func StartMacVNC(defaultPort int) (*exec.Cmd, int, error) {
	// macOS Screen Sharing listens on port 5900.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5900", 2*time.Second)
	if err != nil {
		return nil, 0, fmt.Errorf("macOS Screen Sharing is not enabled. " +
			"Enable it in System Settings > General > Sharing > Screen Sharing, " +
			"or run: sudo \"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart\" " +
			"-activate -configure -access -on -users $USER -privs -all -restart -agent")
	}
	_ = conn.Close()

	// Port is open — check that the current user has control (not just observe) privileges.
	if hasControl, checkErr := CheckMacARDControl(); checkErr != nil {
		log.Printf("desktop: could not verify ARD control privileges: %v", checkErr)
	} else if !hasControl {
		return nil, 0, fmt.Errorf("macOS Screen Sharing is enabled but only in observe-only mode. " +
			"Remote mouse and keyboard input will not work. Grant full control with: " +
			"sudo \"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart\" " +
			"-configure -access -on -users $USER -privs -all -restart -agent")
	}

	return nil, 5900, nil
}

// checkMacARDControl checks whether the current user has ARD control privileges
// (not just observe). It reads the naprivs attribute via dscl — if bit 1 is set,
// the user can send mouse/keyboard input over VNC. Returns (true, nil) if control
// is granted, (false, nil) if observe-only, or (false, err) if detection failed.
func CheckMacARDControl() (bool, error) {
	user := os.Getenv("USER")
	if user == "" {
		return false, fmt.Errorf("USER environment variable not set")
	}
	if !IsSafeLocalUsername(user) {
		return false, fmt.Errorf("USER contains unsupported characters")
	}

	// #nosec G702 -- command and args are fixed; USER is validated by IsSafeLocalUsername.
	out, err := securityruntime.CommandOutput("dscl", ".", "-read", "/Users/"+user, "dsAttrTypeNative:naprivs")
	if err != nil {
		// No naprivs key means no ARD privileges configured for this user.
		// This could mean "all local users" mode is active — check that.
		allOut, allErr := securityruntime.CommandOutput(
			"defaults", "read",
			"/Library/Preferences/com.apple.RemoteManagement", "ARD_AllLocalUsers",
		)
		if allErr == nil && strings.TrimSpace(string(allOut)) == "1" {
			return true, nil // All local users have access.
		}
		return false, nil
	}

	// Parse "dsAttrTypeNative:naprivs: <value>" or "dsAttrTypeNative:naprivs:\n <value>"
	raw := strings.TrimSpace(string(out))
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) < 3 {
		return false, fmt.Errorf("unexpected dscl output: %s", raw)
	}
	valStr := strings.TrimSpace(parts[2])

	privs, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return false, fmt.Errorf("failed to parse naprivs value %q: %w", valStr, err)
	}

	// Bit 1 (0x2) = Control and Observe. Without this, VNC is observe-only.
	const ardControlBit = 0x2
	return privs&ardControlBit != 0, nil
}

func IsSafeLocalUsername(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '_', '-', '.':
			continue
		default:
			return false
		}
	}
	return true
}

// startWindowsVNC probes for common Windows VNC servers.
func StartWindowsVNC(defaultPort int) (*exec.Cmd, int, error) {
	// Check if a VNC server is already running.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5900", 2*time.Second)
	if err == nil {
		_ = conn.Close()
		return nil, 5900, nil
	}

	// Try known VNC server executables.
	for _, name := range []string{"tvnserver", "vncserver", "winvnc4"} {
		path, lookErr := exec.LookPath(name)
		if lookErr == nil {
			cmd, cmdErr := securityruntime.NewCommand(path, "-run")
			if cmdErr != nil {
				continue
			}
			if startErr := cmd.Start(); startErr == nil {
				return cmd, 5900, nil
			}
		}
	}

	return nil, 0, fmt.Errorf("no VNC server found on Windows. Install TightVNC, TigerVNC, or UltraVNC")
}
