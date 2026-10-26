package docker

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/labtether/labtether-agent/internal/agentcore/streaminput"
	"github.com/labtether/protocol"
)

var errDockerExecSetupTimeout = errors.New("Docker exec startup timed out")

type pendingExecStart struct {
	ctx    context.Context
	cancel context.CancelFunc
	expire context.CancelCauseFunc
}

func (em *DockerExecManager) HandleExecStart(transport Transport, msg protocol.Message) {
	if start := em.PrepareExecStart(transport, msg); start != nil {
		start()
	}
}

// PrepareExecStart reserves before asynchronous network work so close cannot
// overtake creation and an old startup cannot publish over a replacement.
func (em *DockerExecManager) PrepareExecStart(transport Transport, msg protocol.Message) func() {
	var req protocol.DockerExecStartData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("docker-exec: invalid start request: %v", err)
		return nil
	}

	if req.SessionID == "" || req.ContainerID == "" {
		log.Printf("docker-exec: missing session_id or container_id")
		return nil
	}
	if !isValidContainerID(req.ContainerID) {
		log.Printf("docker-exec: invalid container_id %q", req.ContainerID)
		return func() { sendExecClosed(transport, req.SessionID, "invalid container ID") }
	}

	em.mu.Lock()
	if _, exists := em.sessions[req.SessionID]; exists || em.pending[req.SessionID] != nil {
		em.mu.Unlock()
		return nil
	}
	if len(em.sessions)+len(em.pending) >= maxExecSessions {
		em.mu.Unlock()
		return func() { sendExecClosed(transport, req.SessionID, "max exec sessions reached") }
	}
	if em.pending == nil {
		em.pending = make(map[string]*pendingExecStart)
	}
	startCtx := context.Background()
	if owner, ok := transport.(interface{ Context() context.Context }); ok {
		startCtx = owner.Context()
	}
	ctx, cancelCause := context.WithCancelCause(startCtx)
	cancel := func() { cancelCause(context.Canceled) }
	pending := &pendingExecStart{ctx: ctx, cancel: cancel, expire: cancelCause}
	em.pending[req.SessionID] = pending
	em.mu.Unlock()
	return func() { em.startExec(transport, req, pending) }
}

func (em *DockerExecManager) startExec(transport Transport, req protocol.DockerExecStartData, pending *pendingExecStart) {
	ctx, cancel := pending.ctx, pending.cancel
	defer func() {
		em.mu.Lock()
		if em.pending[req.SessionID] == pending {
			delete(em.pending, req.SessionID)
			cancel()
		}
		em.mu.Unlock()
	}()
	if ctx.Err() != nil {
		return
	}
	// Bound create/upgrade without placing a deadline on the interactive shell.
	budget := em.setupTimeout
	if budget <= 0 {
		budget = 5 * time.Minute
	}
	timer := time.AfterFunc(budget, func() { pending.expire(errDockerExecSetupTimeout) })
	defer timer.Stop()
	// Create exec instance
	cmd := req.Command
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh"}
	}
	execID, err := em.client.createExec(ctx, req.ContainerID, cmd, req.TTY)
	if err != nil {
		log.Printf("docker-exec: failed to create exec: %v", err)
		em.sendPendingExecFailure(transport, req.SessionID, pending, "failed to create exec: "+err.Error())
		return
	}

	// Start exec and hijack the connection for bidirectional I/O.
	conn, err := em.startAndHijack(ctx, execID, req.TTY)
	if err != nil {
		log.Printf("docker-exec: failed to start exec: %v", err)
		em.sendPendingExecFailure(transport, req.SessionID, pending, "failed to start exec: "+err.Error())
		return
	}

	if !timer.Stop() {
		// Stop losing the race means setup has expired, even if the callback
		// has not run yet. Never publish that connection as an active owner.
		pending.expire(errDockerExecSetupTimeout)
	}
	if ctx.Err() != nil {
		_ = conn.Close()
		em.sendPendingExecFailure(transport, req.SessionID, pending, context.Cause(ctx).Error())
		return
	}

	sess := &dockerExecSession{
		ctx:       ctx,
		sessionID: req.SessionID,
		execID:    execID,
		conn:      conn,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	sess.inputWriter = streaminput.New(conn, func(err error) {
		sess.setReasonIfUnset("stdin write failed: " + err.Error())
		sess.cancel()
	})

	em.mu.Lock()
	if em.pending[req.SessionID] != pending || ctx.Err() != nil {
		em.mu.Unlock()
		_ = sess.closeInput()
		cancel()
		return
	}
	delete(em.pending, req.SessionID)
	em.sessions[req.SessionID] = sess
	em.mu.Unlock()

	// Notify hub that exec is ready.
	sendExecStarted(transport, req.SessionID)

	// Stream output → hub.
	go em.streamExecOutput(transport, sess)

	// Wait for connection to close and clean up.
	go func() {
		<-sess.done
		if em.cleanupSession(sess) {
			sendExecClosed(transport, req.SessionID, sess.reasonOr("exec ended"))
		}
	}()
}

func (em *DockerExecManager) sendPendingExecFailure(transport Transport, id string, pending *pendingExecStart, reason string) {
	em.mu.Lock()
	current := em.pending[id] == pending && (pending.ctx.Err() == nil || errors.Is(context.Cause(pending.ctx), errDockerExecSetupTimeout))
	em.mu.Unlock()
	if current {
		sendExecClosed(transport, id, reason)
	}
}
