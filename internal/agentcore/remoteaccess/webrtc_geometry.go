package remoteaccess

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

type webRTCCaptureGeometry struct {
	sourceWidth, sourceHeight int
	videoWidth, videoHeight   int
}

var xrandrCurrentGeometry = regexp.MustCompile(`\bcurrent\s+(\d+)\s+x\s+(\d+)\b`)
var ReadWebRTCCaptureGeometry = readWebRTCCaptureGeometry

// ximagesrc captures the root window, so use that exact X11 screen geometry.
// Monitor bounds and a Wayland PipeWire node must not be guessed from the
// requested encoder size or from an unrelated primary monitor.
func readWebRTCCaptureGeometry(ctx context.Context, display, xauthPath string) (int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd, err := securityruntime.NewCommandContext(ctx, "xrandr", "--current")
	if err != nil {
		return 0, 0, err
	}
	cmd.Env = append(BuildX11ClientEnv(display, xauthPath), "LC_ALL=C")
	cmd.WaitDelay = 500 * time.Millisecond
	out, err := securityruntime.CaptureOutput(cmd, 64*1024)
	if err != nil {
		return 0, 0, err
	}
	return parseWebRTCCaptureGeometry(string(out))
}

func parseWebRTCCaptureGeometry(output string) (int, int, error) {
	match := xrandrCurrentGeometry.FindStringSubmatch(output)
	if match == nil {
		return 0, 0, fmt.Errorf("X11 root screen geometry unavailable")
	}
	width, widthErr := strconv.Atoi(match[1])
	height, heightErr := strconv.Atoi(match[2])
	if widthErr != nil || heightErr != nil || width <= 0 || height <= 0 || width > 65535 || height > 65535 {
		return 0, 0, fmt.Errorf("invalid X11 root screen geometry")
	}
	return width, height, nil
}

func (geometry webRTCCaptureGeometry) mapInput(evt WebRTCInputEvent) WebRTCInputEvent {
	if geometry.sourceWidth <= 0 || geometry.sourceHeight <= 0 || geometry.videoWidth <= 0 || geometry.videoHeight <= 0 {
		return evt
	}
	mapAxis := func(value, encodedSize, sourceSize int) int {
		value = max(0, min(value, encodedSize-1))
		if encodedSize == 1 || sourceSize == 1 {
			return 0
		}
		// The client clamps to the last encoded pixel. Keep that endpoint
		// reachable without shifting interior coordinates (including center).
		if value == encodedSize-1 {
			return sourceSize - 1
		}
		return int(int64(value) * int64(sourceSize) / int64(encodedSize))
	}
	evt.X = mapAxis(evt.X, geometry.videoWidth, geometry.sourceWidth)
	evt.Y = mapAxis(evt.Y, geometry.videoHeight, geometry.sourceHeight)
	return evt
}

// Keep source aspect ratio inside the requested output bounds. Both dimensions
// are even for H.264; explicit square pixels/no borders in the capture pipeline
// make the same full-frame mapping apply to browsers and input injection.
func fitWebRTCVideoSize(sourceWidth, sourceHeight, width, height int) (int, int) {
	fittedWidth := width
	fittedHeight := int(int64(sourceHeight) * int64(width) / int64(sourceWidth))
	if fittedHeight > height {
		fittedHeight = height
		fittedWidth = int(int64(sourceWidth) * int64(height) / int64(sourceHeight))
	}
	return max(2, fittedWidth&^1), max(2, fittedHeight&^1)
}
