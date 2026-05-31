package remoteaccess

import (
	"strconv"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"

	"github.com/pion/webrtc/v4"
)

type WebRTCConfig struct {
	Enabled                    bool
	STUNURL                    string
	TURNURL                    string
	TURNUser                   string
	TURNPass                   string
	WaylandExperimentalEnabled bool
	WaylandPipeWireNodeID      string
	WaylandInputBackend        string
	FPS                        int
}

const (
	defaultWebRTCWidth  = 1920
	defaultWebRTCHeight = 1080
	maxWebRTCWidth      = 7680
	maxWebRTCHeight     = 4320
	minWebRTCFPS        = 5
	defaultWebRTCFPS    = 30
	maxWebRTCFPS        = 120
)

func LoadWebRTCConfig(settings map[string]string) WebRTCConfig {
	cfg := WebRTCConfig{
		Enabled: true,
		STUNURL: "stun:stun.l.google.com:19302",
		FPS:     defaultWebRTCFPS,
	}

	if v, ok := settings[sysconfig.SettingKeyWebRTCEnabled]; ok {
		if enabled, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.Enabled = enabled
		}
	}
	if v := strings.TrimSpace(settings[sysconfig.SettingKeyWebRTCSTUNURL]); v != "" {
		cfg.STUNURL = v
	}
	if v := strings.TrimSpace(settings[sysconfig.SettingKeyWebRTCTURNURL]); v != "" {
		cfg.TURNURL = v
	}
	cfg.TURNUser = strings.TrimSpace(settings[sysconfig.SettingKeyWebRTCTURNUser])
	cfg.TURNPass = strings.TrimSpace(settings[sysconfig.SettingKeyWebRTCTURNPass])
	if v, ok := settings[sysconfig.SettingKeyWebRTCWaylandExperimentalEnabled]; ok {
		if enabled, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.WaylandExperimentalEnabled = enabled
		}
	}
	cfg.WaylandPipeWireNodeID = strings.TrimSpace(settings[sysconfig.SettingKeyWebRTCWaylandPipeWireNodeID])
	cfg.WaylandInputBackend = strings.TrimSpace(strings.ToLower(settings[sysconfig.SettingKeyWebRTCWaylandInputBackend]))
	if cfg.WaylandInputBackend == "" {
		cfg.WaylandInputBackend = "auto"
	}

	if raw := strings.TrimSpace(settings[sysconfig.SettingKeyCaptureFPS]); raw != "" {
		if fps, err := strconv.Atoi(raw); err == nil {
			if fps < minWebRTCFPS {
				fps = minWebRTCFPS
			}
			if fps > maxWebRTCFPS {
				fps = maxWebRTCFPS
			}
			cfg.FPS = fps
		}
	}

	return cfg
}

func (c WebRTCConfig) iceServers() []webrtc.ICEServer {
	servers := make([]webrtc.ICEServer, 0, 2)
	if strings.TrimSpace(c.STUNURL) != "" {
		servers = append(servers, webrtc.ICEServer{URLs: []string{strings.TrimSpace(c.STUNURL)}})
	}
	if strings.TrimSpace(c.TURNURL) != "" {
		servers = append(servers, webrtc.ICEServer{
			URLs:       []string{strings.TrimSpace(c.TURNURL)},
			Username:   c.TURNUser,
			Credential: c.TURNPass,
		})
	}
	return servers
}
