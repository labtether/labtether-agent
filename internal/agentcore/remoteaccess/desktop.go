package remoteaccess

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
	"github.com/labtether/protocol"
)

var DesktopDebugEnabled = sync.OnceValue(func() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("LABTETHER_DESKTOP_DEBUG")), "true")
})

var StartDesktopVNCServer = StartVNCServer
var DialDesktopVNC = net.DialTimeout

// DesktopSession tracks an active VNC desktop session on the agent.
type DesktopSession struct {
	sessionID      string
	vncCmd         *exec.Cmd // nil if using pre-existing VNC server
	xvfbCmd        *exec.Cmd // nil if no Xvfb headless fallback was used
	bootstrapCmd   *exec.Cmd // nil if no fallback shell/window was started
	vncConn        net.Conn
	inputWriter    *streaminput.Writer
	vncAuthFile    string
	port           int
	done           chan struct{}
	closeOnce      sync.Once
	ManagedDisplay string // non-empty if display lifecycle is owned by DisplayManager
}

const MaxDesktopSessions = 10

// DesktopManager manages VNC desktop sessions on the agent.
type DesktopManager struct {
	Mu         sync.Mutex
	Sessions   map[string]*DesktopSession
	DisplayMgr *DisplayManager
	pending    map[string]*pendingDesktopStart
}

func NewDesktopManager(dispMgr *DisplayManager) *DesktopManager {
	return &DesktopManager{
		Sessions:   make(map[string]*DesktopSession),
		DisplayMgr: dispMgr,
	}
}

// handleDesktopData writes incoming VNC data to the local VNC connection.
func (dm *DesktopManager) HandleDesktopData(msg protocol.Message) {
	var payload protocol.DesktopDataPayload
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("desktop: failed to unmarshal input data: %v", err)
		return
	}

	dm.Mu.Lock()
	sess, ok := dm.Sessions[payload.SessionID]
	dm.Mu.Unlock()
	if !ok || sess == nil {
		log.Printf("desktop: input data for unknown session %s", payload.SessionID)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		log.Printf("desktop: failed to decode input data for session %s: %v", payload.SessionID, err)
		return
	}

	if sess.inputWriter != nil {
		_ = sess.inputWriter.Enqueue(decoded)
	}
}

// handleDesktopClose terminates a desktop session.
func (dm *DesktopManager) HandleDesktopClose(msg protocol.Message) {
	if stop := dm.PrepareDesktopClose(msg); stop != nil {
		stop()
	}
}

func (dm *DesktopManager) PrepareDesktopClose(msg protocol.Message) func() {
	var req protocol.DesktopCloseData
	if json.Unmarshal(msg.Data, &req) != nil {
		return nil
	}
	dm.Mu.Lock()
	if pending := dm.pending[req.SessionID]; pending != nil {
		pending.cancel()
		delete(dm.pending, req.SessionID)
	}
	sess := dm.Sessions[req.SessionID]
	delete(dm.Sessions, req.SessionID)
	dm.Mu.Unlock()
	if sess == nil {
		return nil
	}
	return func() { dm.closeSessionResources(sess) }
}

// closeAll terminates all active desktop sessions (called on agent shutdown).
func (dm *DesktopManager) CloseAll() {
	dm.Mu.Lock()
	for id, pending := range dm.pending {
		pending.cancel()
		delete(dm.pending, id)
	}
	sessions := make([]*DesktopSession, 0, len(dm.Sessions))
	for _, sess := range dm.Sessions {
		sessions = append(sessions, sess)
	}
	dm.Sessions = make(map[string]*DesktopSession)
	dm.Mu.Unlock()

	for _, sess := range sessions {
		dm.closeSessionResources(sess)
	}
}

// streamVNCOutput reads from the VNC TCP connection and sends to the hub.
func (dm *DesktopManager) streamVNCOutput(transport MessageSender, sess *DesktopSession) {
	buf := make([]byte, 16384)
	var totalBytes int64
	var frameCount int64
	lastLog := time.Now()
	for {
		n, err := sess.vncConn.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
			frameCount++
			if DesktopDebugEnabled() && time.Since(lastLog) > 5*time.Second {
				log.Printf("desktop-debug: session=%s vnc_output bytes=%d frames=%d", sess.sessionID, totalBytes, frameCount)
				lastLog = time.Now()
			}
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			data, _ := json.Marshal(protocol.DesktopDataPayload{
				SessionID: sess.sessionID,
				Data:      encoded,
			})
			if sendErr := transport.Send(protocol.Message{
				Type: protocol.MsgDesktopData,
				ID:   sess.sessionID,
				Data: data,
			}); sendErr != nil {
				// A failed Hub transport must not keep the VNC stream alive.
				dm.cleanupSession(sess)
				return
			}
		}
		if err != nil {
			log.Printf("desktop: VNC stream ended for session %s after %d bytes %d frames: %v", sess.sessionID, totalBytes, frameCount, err)
			if dm.cleanupSession(sess) {
				SendDesktopClosed(transport, sess.sessionID, sess.inputWriter.Reason("VNC connection closed"))
			}
			return
		}
	}
}

func (dm *DesktopManager) watchXvfbExit(transport MessageSender, sess *DesktopSession) {
	if sess.xvfbCmd == nil || sess.xvfbCmd.Process == nil {
		return
	}
	_ = sess.xvfbCmd.Wait()
	// Check if session is still active (not already cleaned up).
	dm.Mu.Lock()
	current, stillActive := dm.Sessions[sess.sessionID]
	dm.Mu.Unlock()
	if stillActive && current == sess {
		log.Printf("desktop: Xvfb exited unexpectedly for session %s, closing", sess.sessionID)
		if dm.cleanupSession(sess) {
			SendDesktopClosed(transport, sess.sessionID, "Xvfb process exited unexpectedly")
		}
	}
}

func (dm *DesktopManager) cleanup(sessionID string) {
	dm.Mu.Lock()
	sess, ok := dm.Sessions[sessionID]
	if ok {
		delete(dm.Sessions, sessionID)
	}
	dm.Mu.Unlock()
	if ok {
		dm.closeSessionResources(sess)
	}
}

// cleanupSession prevents an old stream exit from deleting a replacement.
func (dm *DesktopManager) cleanupSession(sess *DesktopSession) bool {
	dm.Mu.Lock()
	current := dm.Sessions[sess.sessionID] == sess
	if current {
		delete(dm.Sessions, sess.sessionID)
	}
	dm.Mu.Unlock()
	dm.closeSessionResources(sess)
	return current
}

func (dm *DesktopManager) closeSessionResources(sess *DesktopSession) {
	if sess == nil {
		return
	}
	sess.closeOnce.Do(func() {
		if sess.inputWriter != nil {
			_ = sess.inputWriter.Close()
		}
		if sess.vncConn != nil {
			_ = sess.vncConn.Close()
		}
		TerminateProcess(sess.vncCmd)
		if sess.ManagedDisplay != "" && dm.DisplayMgr != nil {
			dm.DisplayMgr.release(sess.ManagedDisplay)
		} else {
			TerminateProcess(sess.xvfbCmd)
		}
		TerminateProcess(sess.bootstrapCmd)
		RemoveVNCAuthDir(sess.vncAuthFile)
		if sess.done != nil {
			close(sess.done)
		}
	})
}

func TerminateProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func SendDesktopStarted(transport MessageSender, sessionID string, width, height int) {
	data, _ := json.Marshal(protocol.DesktopStartedData{
		SessionID: sessionID,
		Width:     width,
		Height:    height,
	})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDesktopStarted,
		ID:   sessionID,
		Data: data,
	})
}

func SendDesktopClosed(transport MessageSender, sessionID, reason string) {
	data, _ := json.Marshal(protocol.DesktopCloseData{SessionID: sessionID, Reason: reason})
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDesktopClosed,
		ID:   sessionID,
		Data: data,
	})
}
