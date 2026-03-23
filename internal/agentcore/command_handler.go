package agentcore

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"

	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

// defaultCommandTimeout is defined in remoteaccess_aliases.go

// receiveLoop reads incoming messages from the hub over the WebSocket transport and
// dispatches them (primarily command requests, terminal sessions, desktop sessions,
// file operations, process queries, service management, disk queries, network
// queries, package inventory queries, cron/timer visibility queries, user session
// queries, clipboard operations, audio sideband, and Docker management).
func receiveLoop(ctx context.Context, transport *wsTransport, cfg RuntimeConfig, runtime *Runtime,
	termMgr *terminalManager, deskMgr *desktopManager, webrtcMgr *webrtcManager, fileMgr *files.Manager,
	processMgr *system.ProcessManager, serviceMgr *backends.ServiceManager, journalMgr *backends.JournalManager, diskMgr *system.DiskManager, networkMgr *networkManager, packageMgr *backends.PackageManager, cronMgr *backends.CronManager, usersMgr *system.UsersManager,
	clipMgr *clipboardManager, audioMgr *audioSidebandManager,
	dockerCollector *docker.DockerCollector, webServiceCollector *WebServiceCollector, execMgr *docker.DockerExecManager, dockerLogMgr *docker.DockerLogManager) {
	// Display manager must close after both desktop and WebRTC managers (LIFO order).
	if deskMgr.DisplayMgr != nil {
		defer deskMgr.DisplayMgr.CloseAll()
	}
	defer termMgr.CloseAll()
	defer deskMgr.CloseAll()
	if webrtcMgr != nil {
		defer webrtcMgr.CloseAll()
	}
	defer fileMgr.CloseAll()
	if processMgr != nil {
		defer processMgr.CloseAll()
	}
	if serviceMgr != nil {
		defer serviceMgr.CloseAll()
	}
	if journalMgr != nil {
		defer journalMgr.CloseAll()
	}
	if diskMgr != nil {
		defer diskMgr.CloseAll()
	}
	if networkMgr != nil {
		defer networkMgr.CloseAll()
	}
	if packageMgr != nil {
		defer packageMgr.CloseAll()
	}
	if cronMgr != nil {
		defer cronMgr.CloseAll()
	}
	if usersMgr != nil {
		defer usersMgr.CloseAll()
	}
	if clipMgr != nil {
		defer clipMgr.CloseAll()
	}
	if audioMgr != nil {
		defer audioMgr.CloseAll()
	}
	if execMgr != nil {
		defer execMgr.CloseAll()
	}
	if dockerLogMgr != nil {
		defer dockerLogMgr.CloseAll()
	}

	// Semaphore limiting concurrent heavy command handlers to avoid unbounded
	// goroutine growth under load.
	const maxConcurrentHandlers = 20
	sem := make(chan struct{}, maxConcurrentHandlers)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !transport.Connected() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}

		msg, err := transport.Receive()
		if err != nil {
			if transport.Connected() {
				if websocket.IsCloseError(err, websocket.CloseGoingAway) {
					log.Printf("agentws: hub shutting down, will reconnect immediately")
				} else {
					log.Printf("agentws: receive error: %v", err)
				}
				transport.markDisconnected()
			}
			continue
		}

		switch msg.Type {
		case protocol.MsgCommandRequest:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				handleCommandRequest(transport, msg, cfg)
			}()
		case protocol.MsgPing:
			// Lightweight — no semaphore.
			_ = transport.Send(protocol.Message{Type: protocol.MsgPong})
		case protocol.MsgConfigUpdate:
			// Lightweight — no semaphore.
			handleConfigUpdate(transport, msg, runtime)
		case protocol.MsgAgentSettingsApply:
			// Lightweight — no semaphore.
			handleAgentSettingsApply(transport, msg, runtime)
		case protocol.MsgUpdateRequest:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				handleUpdateRequest(transport, msg, cfg)
			}()
		case protocol.MsgTerminalProbe:
			// Lightweight — no semaphore.
			termMgr.HandleTerminalProbe(transport)
		case protocol.MsgTerminalStart:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				termMgr.HandleTerminalStart(transport, msg)
			}()
		case protocol.MsgTerminalData:
			// Lightweight — no semaphore.
			termMgr.HandleTerminalData(msg)
		case protocol.MsgTerminalResize:
			// Lightweight — no semaphore.
			termMgr.HandleTerminalResize(msg)
		case protocol.MsgTerminalTmuxKill:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				termMgr.HandleTerminalTmuxKill(transport, msg)
			}()
		case protocol.MsgTerminalClose:
			// Lightweight — no semaphore.
			termMgr.HandleTerminalClose(msg)
		case protocol.MsgSSHKeyInstall:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				handleSSHKeyInstall(transport, msg)
			}()
		case protocol.MsgSSHKeyRemove:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				handleSSHKeyRemove(transport, msg)
			}()
		case protocol.MsgDesktopStart:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				deskMgr.HandleDesktopStart(transport, msg)
			}()
		case protocol.MsgDesktopData:
			// Lightweight — no semaphore.
			deskMgr.HandleDesktopData(msg)
		case protocol.MsgDesktopClose:
			// Lightweight — no semaphore.
			deskMgr.HandleDesktopClose(msg)
		case protocol.MsgDesktopListDisplays:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				handleListDisplays(transport, msg)
			}()
		case protocol.MsgDesktopDiagnose:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				handleDesktopDiagnose(transport, msg, deskMgr, webrtcMgr)
			}()
		case protocol.MsgWebRTCStart:
			if webrtcMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					webrtcMgr.HandleWebRTCStart(transport, msg)
				}()
			}
		case protocol.MsgWebRTCOffer:
			if webrtcMgr != nil {
				// Offer handling is signaling-only and lightweight.
				webrtcMgr.HandleWebRTCOffer(msg, transport)
			}
		case protocol.MsgWebRTCICE:
			if webrtcMgr != nil {
				// ICE candidate handling is lightweight.
				webrtcMgr.HandleWebRTCICE(msg)
			}
		case protocol.MsgWebRTCInput:
			if webrtcMgr != nil {
				// Input relay is lightweight.
				webrtcMgr.HandleWebRTCInput(msg)
			}
		case protocol.MsgWebRTCStop:
			if webrtcMgr != nil {
				// Stop is lightweight.
				webrtcMgr.HandleWebRTCStop(msg, transport)
			}
		case protocol.MsgWoLSend:
			// Lightweight — no semaphore.
			system.HandleWoLSend(transport, msg)
		case protocol.MsgFileList:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileList(transport, msg)
			}()
		case protocol.MsgFileRead:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileRead(transport, msg)
			}()
		case protocol.MsgFileWrite:
			// Lightweight — no semaphore.
			fileMgr.HandleFileWrite(transport, msg)
		case protocol.MsgFileMkdir:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileMkdir(transport, msg)
			}()
		case protocol.MsgFileDelete:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileDelete(transport, msg)
			}()
		case protocol.MsgFileRename:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileRename(transport, msg)
			}()
		case protocol.MsgFileCopy:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileCopy(transport, msg)
			}()
		case protocol.MsgFileSearch:
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				fileMgr.HandleFileSearch(transport, msg)
			}()
		case protocol.MsgProcessList:
			if processMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					processMgr.HandleProcessList(transport, msg)
				}()
			}
		case protocol.MsgProcessKill:
			if processMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					processMgr.HandleProcessKill(transport, msg)
				}()
			}
		case protocol.MsgServiceList:
			if serviceMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					serviceMgr.HandleServiceList(transport, msg)
				}()
			}
		case protocol.MsgServiceAction:
			if serviceMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					serviceMgr.HandleServiceAction(transport, msg)
				}()
			}
		case protocol.MsgJournalQuery:
			if journalMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					journalMgr.HandleJournalQuery(transport, msg)
				}()
			}
		case protocol.MsgDiskList:
			if diskMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					diskMgr.HandleDiskList(transport, msg)
				}()
			}
		case protocol.MsgNetworkList:
			if networkMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					networkMgr.HandleNetworkList(transport, msg)
				}()
			}
		case protocol.MsgNetworkAction:
			if networkMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					networkMgr.HandleNetworkAction(transport, msg)
				}()
			}
		case protocol.MsgPackageList:
			if packageMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					packageMgr.HandlePackageList(transport, msg)
				}()
			}
		case protocol.MsgPackageAction:
			if packageMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					packageMgr.HandlePackageAction(transport, msg)
				}()
			}
		case protocol.MsgCronList:
			if cronMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					cronMgr.HandleCronList(transport, msg)
				}()
			}
		case protocol.MsgUsersList:
			if usersMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					usersMgr.HandleUsersList(transport, msg)
				}()
			}
		case protocol.MsgAlertNotify:
			// Lightweight — no semaphore.
			handleAlertNotify(msg, runtime)
		case protocol.MsgEnrollmentChallenge:
			// Lightweight — no semaphore.
			handleEnrollmentChallenge(transport, msg, cfg)
		case protocol.MsgEnrollmentApproved:
			// Lightweight — no semaphore.
			handleEnrollmentApproved(transport, msg, cfg)
		case protocol.MsgEnrollmentRejected:
			// Lightweight — no semaphore.
			handleEnrollmentRejected(msg)
		// Clipboard messages.
		case protocol.MsgClipboardGet:
			if clipMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					clipMgr.HandleClipboardGet(transport, msg)
				}()
			}
		case protocol.MsgClipboardSet:
			if clipMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					clipMgr.HandleClipboardSet(transport, msg)
				}()
			}
		// Desktop audio sideband messages.
		case protocol.MsgDesktopAudioStart:
			if audioMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					audioMgr.HandleAudioStart(transport, msg)
				}()
			}
		case protocol.MsgDesktopAudioStop:
			// Lightweight — no semaphore.
			if audioMgr != nil {
				audioMgr.HandleAudioStop(msg)
			}
		// Docker container management messages.
		case protocol.MsgDockerAction:
			if dockerCollector != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					dockerCollector.HandleDockerAction(transport, msg)
				}()
			}
		case protocol.MsgDockerExecStart:
			if execMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					execMgr.HandleExecStart(transport, msg)
				}()
			}
		case protocol.MsgDockerExecInput:
			// Lightweight — no semaphore.
			if execMgr != nil {
				execMgr.HandleExecInput(msg)
			}
		case protocol.MsgDockerExecResize:
			// Lightweight — no semaphore.
			if execMgr != nil {
				execMgr.HandleExecResize(msg)
			}
		case protocol.MsgDockerExecClose:
			// Lightweight — no semaphore.
			if execMgr != nil {
				execMgr.HandleExecClose(msg)
			}
		case protocol.MsgDockerLogsStart:
			if dockerLogMgr != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					dockerLogMgr.HandleLogsStart(ctx, transport, msg)
				}()
			}
		case protocol.MsgDockerLogsStop:
			// Lightweight — no semaphore.
			if dockerLogMgr != nil {
				dockerLogMgr.HandleLogsStop(msg)
			}
		case protocol.MsgDockerComposeAction:
			if dockerCollector != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					dockerCollector.HandleComposeAction(transport, msg)
				}()
			}
		case protocol.MsgWebServiceSync:
			if webServiceCollector != nil {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					webServiceCollector.RunCycle(ctx)
				}()
			}
		default:
			log.Printf("agentws: unknown message type from hub: %s", msg.Type)
		}
	}
}

// handleAlertNotify processes an alert notification from the hub and caches it locally.
func handleAlertNotify(msg protocol.Message, runtime *Runtime) {
	var data protocol.AlertNotifyData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("agentws: invalid alert.notify: %v", err)
		return
	}

	ts, _ := time.Parse(time.RFC3339, data.Timestamp)
	snapshot := AlertSnapshot{
		ID:        data.ID,
		Severity:  data.Severity,
		Title:     data.Title,
		Summary:   data.Summary,
		State:     data.State,
		Timestamp: ts,
	}
	runtime.pushAlert(snapshot)
	log.Printf("agentws: alert %s [%s] %s: %s", data.ID, data.Severity, data.State, data.Title)
}

// sendTelemetrySample sends a TelemetrySample as a telemetry message over
// the WebSocket transport.
func sendTelemetrySample(transport *wsTransport, sample TelemetrySample) {
	td := protocol.TelemetryData{
		AssetID:          sample.AssetID,
		CPUPercent:       sample.CPUPercent,
		MemoryPercent:    sample.MemoryPercent,
		DiskPercent:      sample.DiskPercent,
		NetRXBytesPerSec: sample.NetRXBytesPerSec,
		NetTXBytesPerSec: sample.NetTXBytesPerSec,
		TempCelsius:      sample.TempCelsius,
	}
	data, err := json.Marshal(td)
	if err != nil {
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgTelemetry,
		Data: data,
	})
}
