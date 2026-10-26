package agentcore

import (
	"github.com/gorilla/websocket"
	"github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
	"log"
	"sync"
)

// Session owner operations run in socket receipt order, before asynchronous
// process/network startup. Their work has a separate bounded lane so close can
// bypass a blocked ordinary command pool.
func dispatchSessionMessage(transport *wsTransport, conn *websocket.Conn, msg protocol.Message, terminals *terminalManager, desktops *desktopManager, execs *docker.DockerExecManager, webrtc *webrtcManager, audio *audioSidebandManager, logs *docker.DockerLogManager, slots chan struct{}, workers *sync.WaitGroup) bool {
	switch msg.Type {
	case protocol.MsgWebRTCInput, protocol.MsgTerminalResize, protocol.MsgDockerExecResize, protocol.MsgWebRTCOffer, protocol.MsgWebRTCICE, protocol.MsgDockerLogsStart, protocol.MsgDockerLogsStop, protocol.MsgDesktopStart, protocol.MsgDesktopData, protocol.MsgDesktopClose, protocol.MsgTerminalStart, protocol.MsgTerminalData, protocol.MsgTerminalClose, protocol.MsgDockerExecStart, protocol.MsgDockerExecInput, protocol.MsgDockerExecClose, protocol.MsgWebRTCStart, protocol.MsgWebRTCStop, protocol.MsgDesktopAudioStart, protocol.MsgDesktopAudioStop:
	default:
		return false
	}
	transport.withCurrentSessionMessage(conn, func(sender *sessionMessageSender) {
		launch := func(name string, start func()) { launchSessionStart(sender, slots, workers, name, start) }
		switch msg.Type {
		case protocol.MsgDesktopStart:
			launch("desktop-start", desktops.PrepareDesktopStart(sender, msg))
		case protocol.MsgDesktopData:
			desktops.HandleDesktopData(msg)
		case protocol.MsgDesktopClose:
			launchSessionClose(workers, desktops.PrepareDesktopClose(msg))
		case protocol.MsgTerminalStart:
			launch("terminal-start", terminals.PrepareTerminalStart(sender, msg))
		case protocol.MsgTerminalResize:
			terminals.HandleTerminalResize(msg)
		case protocol.MsgWebRTCInput:
			if webrtc != nil {
				webrtc.HandleWebRTCInput(msg, sender)
			}
		case protocol.MsgDockerExecResize:
			if execs != nil {
				launch("docker-exec-resize", execs.PrepareExecResize(msg))
			}
		case protocol.MsgWebRTCOffer:
			if webrtc != nil {
				launch("webrtc-offer", webrtc.PrepareWebRTCOffer(msg, sender))
			}
		case protocol.MsgWebRTCICE:
			if webrtc != nil {
				launch("webrtc-ice", webrtc.PrepareWebRTCICE(msg))
			}
		case protocol.MsgDockerLogsStart:
			if logs != nil {
				launch("docker-logs-start", logs.PrepareLogsStart(sender.Context(), sender, msg))
			}
		case protocol.MsgDockerLogsStop:
			if logs != nil {
				logs.HandleLogsStop(msg)
			}
		case protocol.MsgTerminalData:
			terminals.HandleTerminalData(msg)
		case protocol.MsgTerminalClose:
			terminals.HandleTerminalClose(msg)
		case protocol.MsgDockerExecStart:
			if execs != nil {
				launch("docker-exec-start", execs.PrepareExecStart(sender, msg))
			}
		case protocol.MsgDockerExecInput:
			if execs != nil {
				execs.HandleExecInput(msg)
			}
		case protocol.MsgDockerExecClose:
			if execs != nil {
				execs.HandleExecClose(msg)
			}
		case protocol.MsgWebRTCStart:
			if webrtc != nil {
				launch("webrtc-start", webrtc.PrepareWebRTCStart(sender, msg))
			}
		case protocol.MsgWebRTCStop:
			if webrtc != nil {
				launchSessionClose(workers, webrtc.PrepareWebRTCStop(msg, sender))
			}
		case protocol.MsgDesktopAudioStart:
			if audio != nil {
				launch("audio-start", audio.PrepareAudioStart(sender, msg))
			}
		case protocol.MsgDesktopAudioStop:
			if audio != nil {
				launchSessionClose(workers, audio.PrepareAudioStop(sender, msg))
			}
		}
	})
	return true
}

func launchSessionStart(sender *sessionMessageSender, slots chan struct{}, workers *sync.WaitGroup, name string, start func()) {
	if start == nil {
		return
	}
	claimed := false
	select {
	case slots <- struct{}{}:
		claimed = true
	default:
		// Do not stall the reader or silently leave a reserved start. Disconnect
		// cancels this socket's pending contexts; its closure then performs cleanup.
		sender.Close()
	}
	if workers != nil {
		workers.Add(1)
	}
	go func() {
		if workers != nil {
			defer workers.Done()
		}
		if claimed {
			defer func() { <-slots }()
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("agentws: %s panic: %v", name, recovered)
			}
		}()
		start()
	}()
}

// Preparation claims the owner exactly once; duplicate stops return nil.
// Teardown gets no start semaphore because it must unblock those starters.
func launchSessionClose(workers *sync.WaitGroup, closeSession func()) {
	if closeSession == nil {
		return
	}
	if workers != nil {
		workers.Add(1)
	}
	go func() {
		if workers != nil {
			defer workers.Done()
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("agentws: session-close panic: %v", recovered)
			}
		}()
		closeSession()
	}()
}

// A full general pool faults its originating socket. Keeping the reader free
// lets close/cancel reach sessions whose work might otherwise hold that pool.
func launchConnectionHandler(sender *sessionMessageSender, slots chan struct{}, workers *sync.WaitGroup, name string, handle func()) {
	if sender.Context().Err() != nil {
		return
	}
	select {
	case slots <- struct{}{}:
	default:
		sender.Close()
		return
	}
	if workers != nil {
		workers.Add(1)
	}
	go func() {
		defer func() { <-slots }()
		if workers != nil {
			defer workers.Done()
		}
		if sender.Context().Err() == nil {
			safeHandler(name, handle)
		}
	}()
}
