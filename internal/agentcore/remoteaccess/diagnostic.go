package remoteaccess

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

var strictLocalX11DisplayPattern = regexp.MustCompile(`^:[0-9]+(?:\.[0-9]+)?$`)

// desktopDiagnosticCommandTimeout bounds each local probe so a hung tool can
// neither hold a message handler slot nor push the reply past the Hub's wait.
const desktopDiagnosticCommandTimeout = 3 * time.Second

// diagnosticCommandOutput runs one fixed local diagnostic tool with a timeout.
func diagnosticCommandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), desktopDiagnosticCommandTimeout)
	defer cancel()
	// #nosec G204,G702 -- Callers pass fixed diagnostic tool names; the only variable argument is a strictly validated local X11 display.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	return securityruntime.CaptureOutput(cmd, securityruntime.DefaultCommandOutputLimit)
}

// CollectDesktopDiagnostic gathers a snapshot of the desktop stack state on the agent.
// Both deskMgr and webrtcMgr may be nil (e.g. on platforms without desktop support).
func CollectDesktopDiagnostic(deskMgr *DesktopManager, webrtcMgr *WebRTCManager) protocol.DesktopDiagnosticData {
	var d protocol.DesktopDiagnosticData
	session := DetectDesktopSessionFn()
	d.DesktopSessionType = session.Type
	d.DesktopBackend = session.Backend
	d.DesktopUser = session.Username
	d.RealDisplay = session.Display

	// --- X11 environment ---
	d.EnvDisplay = os.Getenv("DISPLAY")

	// Reuse the session found above: the display scan checks up to 100
	// displays and must not ask loginctl again for each one.
	displays := &displayProbe{session: session, sessionKnown: true}
	d.ActiveDisplays = displays.appendActive(d.ActiveDisplays)

	// --- Xvfb state ---
	if out, err := diagnosticCommandOutput("pgrep", "-a", "Xvfb"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			d.XvfbRunning = true
			// "pid args…" — first field is the PID.
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if pid, err := strconv.Atoi(fields[0]); err == nil {
					d.XvfbPIDs = append(d.XvfbPIDs, pid)
				}
			}
			// Extract the display identifier from the command-line args.
			for _, f := range fields[1:] {
				if strings.HasPrefix(f, ":") {
					d.XvfbDisplays = append(d.XvfbDisplays, f)
					break
				}
			}
		}
	}

	// --- x11vnc state ---
	if out, err := diagnosticCommandOutput("pgrep", "-a", "x11vnc"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			d.X11VNCRunning = true
			fields := strings.Fields(line)
			// Parse -display and -rfbport from x11vnc args.
			for i, f := range fields {
				switch f {
				case "-display":
					if i+1 < len(fields) {
						d.X11VNCDisplay = fields[i+1]
					}
				case "-rfbport":
					if i+1 < len(fields) {
						if port, err := strconv.Atoi(fields[i+1]); err == nil {
							d.X11VNCPort = port
						}
					}
				}
			}
		}
	}

	// --- Bootstrap shell ---
	if out, err := diagnosticCommandOutput("pgrep", "-f", "LabTether Desktop"); err == nil {
		if strings.TrimSpace(string(out)) != "" {
			d.BootstrapRunning = true
		}
	}

	// --- xterm availability ---
	if _, err := exec.LookPath("xterm"); err == nil {
		d.XtermAvailable = true
	}

	// --- GStreamer tool availability ---
	if _, err := exec.LookPath("gst-launch-1.0"); err == nil {
		d.GstLaunchAvailable = true
	}
	if _, err := exec.LookPath("gst-inspect-1.0"); err == nil {
		d.GstInspectAvailable = true
	}

	// --- WebRTC capabilities ---
	// Reuse the manager's startup probe. Probing again runs gst-inspect once
	// per element, and without a writable GStreamer cache each run rescans
	// every plugin, which pushed diagnose past the Hub's wait.
	var caps protocol.WebRTCCapabilitiesData
	if webrtcMgr != nil {
		caps = webrtcMgr.caps
	} else {
		caps = DetectWebRTCCapabilities()
	}
	d.VideoEncoders = caps.VideoEncoders
	d.AudioSources = caps.AudioSources
	d.WebRTCAvailable = caps.Available
	d.WebRTCReason = caps.UnavailableReason
	d.VNCRealDesktopSupported = caps.VNCRealDesktopSupported
	d.WebRTCRealDesktopSupported = caps.WebRTCRealDesktopSupported
	d.CaptureBackend = caps.CaptureBackend

	// --- Active session counts ---
	if deskMgr != nil {
		deskMgr.Mu.Lock()
		d.ActiveVNCSessions = len(deskMgr.Sessions)
		deskMgr.Mu.Unlock()
	}
	if webrtcMgr != nil {
		webrtcMgr.Mu.Lock()
		d.ActiveWebRTCSessions = len(webrtcMgr.Sessions)
		webrtcMgr.Mu.Unlock()
	}

	// --- Framebuffer content check ---
	display := d.EnvDisplay
	if display == "" && len(d.XvfbDisplays) > 0 {
		display = d.XvfbDisplays[0]
	}
	display = NormalizeX11DisplayIdentifier(display)
	if display != "" && !strictLocalX11DisplayPattern.MatchString(display) {
		d.FramebufferError = "unsupported X11 display identifier"
	}
	if display != "" && strictLocalX11DisplayPattern.MatchString(display) {
		out, err := diagnosticCommandOutput("xdpyinfo", "-display", display)
		if err != nil {
			d.FramebufferError = err.Error()
		} else if strings.Contains(string(out), "dimensions:") {
			d.FramebufferHasContent = true
		}
	}

	return d
}

// handleDesktopDiagnose handles a MsgDesktopDiagnose request from the hub.
func HandleDesktopDiagnose(transport MessageSender, msg protocol.Message, deskMgr *DesktopManager, webrtcMgr *WebRTCManager) {
	var req protocol.DesktopDiagnosticRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("desktop-diagnostic: invalid diagnose request: %v", err)
		return
	}

	diag := CollectDesktopDiagnostic(deskMgr, webrtcMgr)
	diag.RequestID = req.RequestID

	data, _ := json.Marshal(diag)
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDesktopDiagnosed,
		ID:   req.RequestID,
		Data: data,
	})
}
