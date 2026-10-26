package remoteaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
	"github.com/labtether/protocol"
	"log"
	"time"
)

type pendingDesktopStart struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (dm *DesktopManager) HandleDesktopStart(transport MessageSender, msg protocol.Message) {
	if start := dm.PrepareDesktopStart(transport, msg); start != nil {
		start()
	}
}

// Reserve in receive order; process startup can finish after cancellation but
// may only publish if this exact reservation still owns the session ID.
func (dm *DesktopManager) PrepareDesktopStart(transport MessageSender, msg protocol.Message) func() {
	var req protocol.DesktopStartData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("desktop: invalid start request: %v", err)
		return nil
	}
	if req.SessionID == "" {
		return nil
	}
	dm.Mu.Lock()
	defer dm.Mu.Unlock()
	if _, exists := dm.Sessions[req.SessionID]; exists {
		return nil
	}
	if dm.pending[req.SessionID] != nil {
		return nil
	}
	if len(dm.Sessions)+len(dm.pending) >= MaxDesktopSessions {
		return func() { SendDesktopClosed(transport, req.SessionID, "max desktop sessions reached") }
	}
	ctx := context.Background()
	if owner, ok := transport.(interface{ Context() context.Context }); ok {
		ctx = owner.Context()
	}
	ctx, cancel := context.WithCancel(ctx)
	pending := &pendingDesktopStart{ctx: ctx, cancel: cancel}
	if dm.pending == nil {
		dm.pending = make(map[string]*pendingDesktopStart)
	}
	dm.pending[req.SessionID] = pending
	return func() { dm.startDesktop(transport, req, pending) }
}
func (dm *DesktopManager) startDesktop(transport MessageSender, req protocol.DesktopStartData, pending *pendingDesktopStart) {
	defer func() {
		pending.cancel()
		dm.Mu.Lock()
		if dm.pending[req.SessionID] == pending {
			delete(dm.pending, req.SessionID)
		}
		dm.Mu.Unlock()
	}()
	if pending.ctx.Err() != nil {
		return
	}
	quality := req.Quality
	if quality == "" {
		quality = "medium"
	}
	vncCmd, xvfbCmd, bootstrapCmd, port, authFile, err := StartDesktopVNCServer(req.Display, quality, req.VNCPassword)
	sess := &DesktopSession{sessionID: req.SessionID, vncCmd: vncCmd, xvfbCmd: xvfbCmd, bootstrapCmd: bootstrapCmd, port: port, vncAuthFile: authFile, done: make(chan struct{})}
	published := false
	defer func() {
		if !published {
			dm.closeSessionResources(sess)
		}
	}()
	if err != nil {
		dm.sendPendingDesktopFailure(transport, req.SessionID, pending, fmt.Sprintf("failed to start VNC: %v", err))
		return
	}
	if pending.ctx.Err() != nil {
		return
	}
	sess.vncConn, err = DialDesktopVNC("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		dm.sendPendingDesktopFailure(transport, req.SessionID, pending, fmt.Sprintf("failed to connect to VNC: %v", err))
		return
	}
	dm.Mu.Lock()
	if dm.pending[req.SessionID] != pending || pending.ctx.Err() != nil {
		dm.Mu.Unlock()
		return
	}
	sess.inputWriter = streaminput.New(sess.vncConn, nil)
	delete(dm.pending, req.SessionID)
	dm.Sessions[req.SessionID] = sess
	published = true
	dm.Mu.Unlock()
	SendDesktopStarted(transport, req.SessionID, req.Width, req.Height)
	go dm.streamVNCOutput(transport, sess)
	if sess.xvfbCmd != nil {
		go dm.watchXvfbExit(transport, sess)
	}
}
func (dm *DesktopManager) sendPendingDesktopFailure(transport MessageSender, id string, pending *pendingDesktopStart, reason string) {
	dm.Mu.Lock()
	current := dm.pending[id] == pending && pending.ctx.Err() == nil
	dm.Mu.Unlock()
	if current {
		SendDesktopClosed(transport, id, reason)
	}
}
