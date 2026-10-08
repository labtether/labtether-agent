package remoteaccess

import (
	"context"
	"encoding/json"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
	"github.com/pion/webrtc/v4"
	"log"
	"os/exec"
	"strings"
	"sync"
)

type WebRTCSession struct {
	sessionID      string
	pc             *webrtc.PeerConnection
	videoTrack     *webrtc.TrackLocalStaticRTP
	audioTrack     *webrtc.TrackLocalStaticRTP
	gstVideoCmd    *exec.Cmd
	gstAudioCmd    *exec.Cmd
	videoLogPath   string
	audioLogPath   string
	videoPort      int
	audioPort      int
	inputCh        chan WebRTCInputEvent
	cancel         context.CancelFunc
	done           chan struct{}
	closeOnce      sync.Once
	resourceMu     sync.Mutex
	closed         bool
	ManagedDisplay string          // non-empty if display was acquired from DisplayManager
	xauthPath      string          // Xauthority for ManagedDisplay when one was created
	dispMgr        *DisplayManager // reference for release on close
	desktopBackend string
	sessionInfo    DesktopSessionInfo
	inputBackend   string
}

const MaxWebRTCSessions = 10

type pendingWebRTCStart struct {
	ctx     context.Context
	cancel  context.CancelFunc
	session *WebRTCSession
}

func (s *WebRTCSession) close(reason string) {
	s.closeOnce.Do(func() {
		s.resourceMu.Lock()
		s.closed = true
		videoCmd := s.gstVideoCmd
		audioCmd := s.gstAudioCmd
		videoLogPath := s.videoLogPath
		audioLogPath := s.audioLogPath
		videoPort := s.videoPort
		audioPort := s.audioPort
		s.gstVideoCmd = nil
		s.gstAudioCmd = nil
		s.videoLogPath = ""
		s.audioLogPath = ""
		s.resourceMu.Unlock()
		log.Printf(
			"webrtc: closing session=%s reason=%s display=%s xauth=%s video_port=%d audio_port=%d",
			s.sessionID,
			strings.TrimSpace(reason),
			ValueOrDash(strings.TrimSpace(s.ManagedDisplay)),
			ValueOrDash(strings.TrimSpace(s.xauthPath)),
			videoPort,
			audioPort,
		)
		if s.cancel != nil {
			s.cancel()
		}
		if videoCmd != nil && videoCmd.Process != nil {
			_ = videoCmd.Process.Kill()
		}
		if audioCmd != nil && audioCmd.Process != nil {
			_ = audioCmd.Process.Kill()
		}
		if s.pc != nil {
			_ = s.pc.Close()
		}
		if s.ManagedDisplay != "" && s.dispMgr != nil {
			s.dispMgr.release(s.ManagedDisplay)
		}
		RemoveProcessLog(videoLogPath)
		RemoveProcessLog(audioLogPath)
		close(s.done)
	})
}

func (s *WebRTCSession) attachVideoPipeline(cmd *exec.Cmd, logPath string) bool {
	return s.attachPipeline(cmd, logPath, false)
}

func (s *WebRTCSession) attachAudioPipeline(cmd *exec.Cmd, logPath string) bool {
	return s.attachPipeline(cmd, logPath, true)
}

func (s *WebRTCSession) attachPipeline(cmd *exec.Cmd, logPath string, audio bool) bool {
	s.resourceMu.Lock()
	if s.closed {
		s.resourceMu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		RemoveProcessLog(logPath)
		return false
	}
	if audio {
		s.gstAudioCmd = cmd
		s.audioLogPath = logPath
	} else {
		s.gstVideoCmd = cmd
		s.videoLogPath = logPath
	}
	s.resourceMu.Unlock()
	return true
}

func (s *WebRTCSession) clearAudioPipeline() {
	s.resourceMu.Lock()
	s.gstAudioCmd = nil
	s.audioLogPath = ""
	s.audioPort = 0
	s.resourceMu.Unlock()
}

type WebRTCManager struct {
	Mu       sync.Mutex
	Sessions map[string]*WebRTCSession
	pending  map[string]*pendingWebRTCStart
	caps     protocol.WebRTCCapabilitiesData
	settings SettingsProvider
	fileMgr  *files.Manager
	dispMgr  *DisplayManager
}

func NewWebRTCManager(caps protocol.WebRTCCapabilitiesData, settings SettingsProvider, fileMgr *files.Manager, dispMgr *DisplayManager) *WebRTCManager {
	return &WebRTCManager{
		Sessions: make(map[string]*WebRTCSession),
		pending:  make(map[string]*pendingWebRTCStart),
		caps:     caps,
		settings: settings,
		fileMgr:  fileMgr,
		dispMgr:  dispMgr,
	}
}

func (wm *WebRTCManager) reserveSessionStart(sessionID string) (*pendingWebRTCStart, string) {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- Cancel is retained until promotion, stop, or manager shutdown.
	pending := &pendingWebRTCStart{ctx: ctx, cancel: cancel}

	wm.Mu.Lock()
	defer wm.Mu.Unlock()
	if wm.pending == nil {
		wm.pending = make(map[string]*pendingWebRTCStart)
	}
	if _, exists := wm.Sessions[sessionID]; exists {
		cancel()
		return nil, "session already exists"
	}
	if _, exists := wm.pending[sessionID]; exists {
		cancel()
		return nil, "session start already in progress"
	}
	if len(wm.Sessions)+len(wm.pending) >= MaxWebRTCSessions {
		cancel()
		return nil, "too many concurrent webrtc sessions"
	}
	wm.pending[sessionID] = pending
	return pending, ""
}

func (wm *WebRTCManager) bindPendingSession(sessionID string, pending *pendingWebRTCStart, session *WebRTCSession) bool {
	wm.Mu.Lock()
	defer wm.Mu.Unlock()
	if wm.pending[sessionID] != pending || pending.ctx.Err() != nil {
		return false
	}
	pending.session = session
	return true
}

func (wm *WebRTCManager) promotePendingSession(sessionID string, pending *pendingWebRTCStart) bool {
	wm.Mu.Lock()
	defer wm.Mu.Unlock()
	if wm.pending[sessionID] != pending || pending.ctx.Err() != nil || pending.session == nil {
		return false
	}
	delete(wm.pending, sessionID)
	wm.Sessions[sessionID] = pending.session
	return true
}

func (wm *WebRTCManager) abortPendingSession(sessionID string, pending *pendingWebRTCStart, reason string) {
	wm.Mu.Lock()
	if wm.pending[sessionID] == pending {
		delete(wm.pending, sessionID)
	} else if pending.session != nil && wm.Sessions[sessionID] == pending.session {
		delete(wm.Sessions, sessionID)
	}
	wm.Mu.Unlock()
	pending.cancel()
	if pending.session != nil {
		pending.session.close(reason)
	}
}

func (wm *WebRTCManager) sendPendingStopped(transport MessageSender, sessionID string, pending *pendingWebRTCStart, reason string) bool {
	wm.Mu.Lock()
	defer wm.Mu.Unlock()
	if wm.pending[sessionID] != pending {
		return false
	}
	SendWebRTCStopped(transport, sessionID, reason)
	return true
}

func (wm *WebRTCManager) sendSessionMessageIfCurrent(transport MessageSender, sessionID string, expected *WebRTCSession, message protocol.Message) bool {
	wm.Mu.Lock()
	defer wm.Mu.Unlock()
	if wm.Sessions[sessionID] != expected {
		return false
	}
	_ = transport.Send(message)
	return true
}

func (wm *WebRTCManager) sessionIsCurrent(sessionID string, expected *WebRTCSession) bool {
	wm.Mu.Lock()
	defer wm.Mu.Unlock()
	return wm.Sessions[sessionID] == expected
}

func (wm *WebRTCManager) HandleWebRTCStop(msg protocol.Message, transport MessageSender) {
	var req protocol.WebRTCStoppedData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.SessionID == "" {
		return
	}
	wm.CleanupWithReason(req.SessionID, "stopped by hub")
	SendWebRTCStopped(transport, req.SessionID, "stopped by hub")
}

func (wm *WebRTCManager) Cleanup(sessionID string) {
	wm.CleanupWithReason(sessionID, "cleanup requested")
}

func (wm *WebRTCManager) MarkAudioPipelineStopped(sessionID string) {
	wm.markAudioPipelineStopped(sessionID, nil)
}

func (wm *WebRTCManager) markAudioPipelineStopped(sessionID string, expected *WebRTCSession) {
	wm.Mu.Lock()
	sess, ok := wm.Sessions[sessionID]
	if !ok {
		if pending := wm.pending[sessionID]; pending != nil && (expected == nil || pending.session == expected) {
			sess = pending.session
			ok = sess != nil
		}
	}
	if !ok || (expected != nil && sess != expected) {
		wm.Mu.Unlock()
		return
	}
	wm.Mu.Unlock()
	sess.clearAudioPipeline()
}

func (wm *WebRTCManager) CleanupWithReason(sessionID, reason string) {
	wm.cleanupSessionInstance(sessionID, nil, reason)
}

func (wm *WebRTCManager) cleanupSessionInstance(sessionID string, expected *WebRTCSession, reason string) bool {
	wm.Mu.Lock()
	sess, ok := wm.Sessions[sessionID]
	if ok && expected != nil && sess != expected {
		wm.Mu.Unlock()
		return false
	}
	var pending *pendingWebRTCStart
	if ok {
		delete(wm.Sessions, sessionID)
	} else if candidate := wm.pending[sessionID]; candidate != nil && (expected == nil || candidate.session == expected) {
		pending = candidate
		sess = candidate.session
		delete(wm.pending, sessionID)
		ok = true
	}
	wm.Mu.Unlock()
	if !ok {
		return false
	}
	if pending != nil {
		pending.cancel()
	}
	log.Printf("webrtc: cleanup session=%s trigger=%s", sessionID, strings.TrimSpace(reason))
	if sess != nil {
		sess.close(reason)
	}
	return true
}

func (wm *WebRTCManager) CloseAll() {
	wm.Mu.Lock()
	sessions := make([]*WebRTCSession, 0, len(wm.Sessions))
	pending := make([]*pendingWebRTCStart, 0, len(wm.pending))
	for id, sess := range wm.Sessions {
		sessions = append(sessions, sess)
		delete(wm.Sessions, id)
	}
	for id, start := range wm.pending {
		pending = append(pending, start)
		delete(wm.pending, id)
	}
	wm.Mu.Unlock()
	for _, start := range pending {
		start.cancel()
		if start.session != nil {
			start.session.close("manager closeAll")
		}
	}
	for _, sess := range sessions {
		sess.close("manager closeAll")
	}
}
