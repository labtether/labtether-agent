package remoteaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/labtether/protocol"
)

var StartAudioCapture = PlatformStartAudioCapture

const (
	audioDefaultBitrate      = 128000
	audioChunkSize           = 4096 // bytes per audio data message
	MaxAudioSidebandSessions = 10
)

type AudioSidebandSession struct {
	cancel context.CancelFunc
}

// AudioSidebandManager manages audio capture sessions for VNC desktop sessions.
// On Linux it shells out to ffmpeg for PulseAudio → Opus encoding.
// On other platforms it reports "unavailable".
type AudioSidebandManager struct {
	Mu       sync.Mutex
	Sessions map[string]*AudioSidebandSession
}

func NewAudioSidebandManager() *AudioSidebandManager {
	return &AudioSidebandManager{
		Sessions: make(map[string]*AudioSidebandSession),
	}
}

// closeAll stops all active audio capture sessions.
func (m *AudioSidebandManager) CloseAll() {
	m.Mu.Lock()
	sessions := make([]*AudioSidebandSession, 0, len(m.Sessions))
	for sid, session := range m.Sessions {
		sessions = append(sessions, session)
		delete(m.Sessions, sid)
	}
	m.Mu.Unlock()
	for _, session := range sessions {
		session.cancel()
	}
}

// handleAudioStart processes a desktop.audio.start message from the hub.
func (m *AudioSidebandManager) HandleAudioStart(transport MessageSender, msg protocol.Message) {
	var req protocol.DesktopAudioStartData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("audio: invalid start request: %v", err)
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.SessionID == "" {
		log.Printf("audio: start request missing session_id")
		return
	}

	bitrate := req.Bitrate
	if bitrate <= 0 {
		bitrate = audioDefaultBitrate
	}

	m.Mu.Lock()
	existing := m.Sessions[req.SessionID]
	if existing != nil {
		m.Mu.Unlock()
		m.sendState(transport, req.SessionID, "unavailable", "audio session already exists")
		return
	}
	if existing == nil && len(m.Sessions) >= MaxAudioSidebandSessions {
		m.Mu.Unlock()
		m.sendState(transport, req.SessionID, "unavailable", "too many concurrent audio sessions")
		return
	}
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- Cancel is stored in the session map and invoked by HandleAudioStop/CloseAll.
	session := &AudioSidebandSession{cancel: cancel}
	m.Sessions[req.SessionID] = session
	m.Mu.Unlock()

	go m.runCapture(ctx, transport, req.SessionID, bitrate, session)
}

// handleAudioStop processes a desktop.audio.stop message from the hub.
func (m *AudioSidebandManager) HandleAudioStop(transport MessageSender, msg protocol.Message) {
	var req protocol.DesktopAudioStopData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("audio: invalid stop request: %v", err)
		return
	}

	req.SessionID = strings.TrimSpace(req.SessionID)
	m.Mu.Lock()
	session, ok := m.Sessions[req.SessionID]
	if ok {
		delete(m.Sessions, req.SessionID)
	}
	m.Mu.Unlock()
	if ok {
		session.cancel()
		m.sendState(transport, req.SessionID, "stopped", "")
	}
}

// runCapture starts platform-specific audio capture and streams data to the hub.
func (m *AudioSidebandManager) runCapture(ctx context.Context, transport MessageSender, sessionID string, bitrate int, session *AudioSidebandSession) {
	reader, err := StartAudioCapture(ctx, sessionID, bitrate)
	if err != nil {
		log.Printf("audio: capture unavailable for session %s: %v", sessionID, err)
		m.sendStateIfCurrent(transport, sessionID, session, "unavailable", err.Error(), true)
		return
	}

	if !m.sendStateIfCurrent(transport, sessionID, session, "started", "", false) {
		return
	}
	log.Printf("audio: capture started for session %s at %d bps", sessionID, bitrate)

	buf := make([]byte, audioChunkSize)
	for {
		select {
		case <-ctx.Done():
			m.sendStateIfCurrent(transport, sessionID, session, "stopped", "", true)
			return
		default:
		}

		n, readErr := reader.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			payload := protocol.DesktopAudioDataPayload{
				SessionID: sessionID,
				Data:      encoded,
				Timestamp: time.Now().UnixMilli(),
			}
			data, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			if !m.sendMessageIfCurrent(transport, sessionID, session, protocol.Message{
				Type: protocol.MsgDesktopAudioData,
				ID:   sessionID,
				Data: data,
			}) {
				return
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				log.Printf("audio: capture read error for session %s: %v", sessionID, readErr)
			}
			m.sendStateIfCurrent(transport, sessionID, session, "stopped", "", true)
			return
		}
	}
}

func (m *AudioSidebandManager) sendStateIfCurrent(transport MessageSender, sessionID string, expected *AudioSidebandSession, state, errMsg string, remove bool) bool {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if m.Sessions[sessionID] != expected {
		return false
	}
	if remove {
		delete(m.Sessions, sessionID)
	}
	m.sendState(transport, sessionID, state, errMsg)
	return true
}

func (m *AudioSidebandManager) sendMessageIfCurrent(transport MessageSender, sessionID string, expected *AudioSidebandSession, message protocol.Message) bool {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if m.Sessions[sessionID] != expected {
		return false
	}
	_ = transport.Send(message)
	return true
}

// sendState sends a desktop.audio.state message to the hub.
func (m *AudioSidebandManager) sendState(transport MessageSender, sessionID, state, errMsg string) {
	payload := protocol.DesktopAudioStateData{
		SessionID: sessionID,
		State:     state,
		Error:     errMsg,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDesktopAudioState,
		ID:   sessionID,
		Data: data,
	})
}
