package remoteaccess

import "time"

// webRTCProbeTimeout bounds one gst-inspect probe. Without a writable
// GStreamer registry cache every probe rescans all plugins, and a hung probe
// would otherwise block capability detection forever.
var webRTCProbeTimeout = 10 * time.Second

// gstElementAvailable reports whether gst-inspect finds element within the
// probe timeout. A probe that times out counts as unavailable.
func gstElementAvailable(inspectPath, element string) bool {
	cmd, err := NewWebRTCSecurityCommand(inspectPath, element)
	if err != nil {
		return false
	}
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return false
	}
	timer := time.AfterFunc(webRTCProbeTimeout, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	return cmd.Wait() == nil
}
