package remoteaccess

import (
	"context"
	"fmt"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func (wm *WebRTCManager) WatchPipelineExit(ctx context.Context, sessionID, streamType string, cmd *exec.Cmd, logPath string, transport MessageSender) {
	wm.watchPipelineExit(ctx, sessionID, nil, streamType, cmd, logPath, transport)
}

func (wm *WebRTCManager) watchPipelineExit(ctx context.Context, sessionID string, expected *WebRTCSession, streamType string, cmd *exec.Cmd, logPath string, transport MessageSender) {
	err := cmd.Wait()
	select {
	case <-ctx.Done():
		RemoveProcessLog(logPath)
		return
	default:
	}
	reason := fmt.Sprintf("%s pipeline stopped", streamType)
	if err != nil {
		reason = fmt.Sprintf("%s pipeline stopped: %v", streamType, err)
	}
	if logTail := strings.TrimSpace(ReadProcessLogTail(logPath, 4096)); logTail != "" {
		log.Printf("webrtc: %s pipeline exit session=%s reason=%s log=%s", streamType, sessionID, reason, SummarizeProcessLogTail(logTail))
	} else {
		log.Printf("webrtc: %s pipeline exit session=%s reason=%s", streamType, sessionID, reason)
	}
	RemoveProcessLog(logPath)
	if streamType == "audio" {
		wm.markAudioPipelineStopped(sessionID, expected)
		log.Printf("webrtc: continuing session=%s without audio after pipeline exit", sessionID)
		return
	}
	if wm.cleanupSessionInstance(sessionID, expected, reason) {
		SendWebRTCStopped(transport, sessionID, reason)
	}
}

func StartWebRTCPipelineWithLog(cmd *exec.Cmd, pattern string) (string, error) {
	logFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("failed to create pipeline log file: %w", err)
	}
	logPath := logFile.Name()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		RemoveProcessLog(logPath)
		return "", err
	}
	if closeErr := logFile.Close(); closeErr != nil {
		log.Printf("webrtc: warning: failed to close pipeline log handle: %v", closeErr)
	}
	return logPath, nil
}

func ReadRTPToTrack(ctx context.Context, port int, track *webrtc.TrackLocalStaticRTP) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Printf("webrtc: resolve RTP port %d failed: %v", port, err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("webrtc: listen RTP port %d failed: %v", port, err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	pkt := &rtp.Packet{}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		if err := pkt.Unmarshal(buf[:n]); err != nil {
			continue
		}
		if writeErr := track.WriteRTP(pkt); writeErr != nil {
			return
		}
	}
}

func FindFreeUDPPort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port, nil
}

func ParsePipelineArgs(pipeline string) []string {
	parts := strings.Fields(strings.TrimSpace(pipeline))
	if len(parts) == 0 {
		return nil
	}
	return parts
}
