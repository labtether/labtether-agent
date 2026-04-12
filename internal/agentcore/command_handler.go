package agentcore

import (
	"context"
	"encoding/json"
	"log"
	"sync"
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

	// Semaphore limiting concurrent command handlers to avoid unbounded
	// goroutine growth under load. All handlers (including lightweight ones)
	// go through the semaphore so panics are contained and WaitGroup tracked.
	const maxConcurrentHandlers = 20
	sem := make(chan struct{}, maxConcurrentHandlers)

	// handlerWG tracks all in-flight handler goroutines so receiveLoop can
	// drain them gracefully on disconnect/shutdown.
	var handlerWG sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			// Wait for in-flight handlers to drain.
			drainDone := make(chan struct{})
			go func() { handlerWG.Wait(); close(drainDone) }()
			select {
			case <-drainDone:
			case <-time.After(5 * time.Second):
				log.Printf("agentws: timed out waiting for handlers to drain")
			}
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
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("command-request", func() {
					handleCommandRequest(transport, msg, cfg)
				})
			}()
		case protocol.MsgPing:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("ping", func() {
					_ = transport.Send(protocol.Message{Type: protocol.MsgPong})
				})
			}()
		case protocol.MsgConfigUpdate:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("config-update", func() {
					handleConfigUpdate(transport, msg, runtime)
				})
			}()
		case protocol.MsgAgentSettingsApply:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("agent-settings-apply", func() {
					handleAgentSettingsApply(transport, msg, runtime)
				})
			}()
		case protocol.MsgUpdateRequest:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("update-request", func() {
					handleUpdateRequest(transport, msg, cfg)
				})
			}()
		case protocol.MsgTerminalProbe:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("terminal-probe", func() {
					termMgr.HandleTerminalProbe(transport)
				})
			}()
		case protocol.MsgTerminalStart:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("terminal-start", func() {
					termMgr.HandleTerminalStart(transport, msg)
				})
			}()
		case protocol.MsgTerminalData:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("terminal-data", func() {
					termMgr.HandleTerminalData(msg)
				})
			}()
		case protocol.MsgTerminalResize:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("terminal-resize", func() {
					termMgr.HandleTerminalResize(msg)
				})
			}()
		case protocol.MsgTerminalTmuxKill:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("terminal-tmux-kill", func() {
					termMgr.HandleTerminalTmuxKill(transport, msg)
				})
			}()
		case protocol.MsgTerminalClose:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("terminal-close", func() {
					termMgr.HandleTerminalClose(msg)
				})
			}()
		case protocol.MsgSSHKeyInstall:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("ssh-key-install", func() {
					handleSSHKeyInstall(transport, msg)
				})
			}()
		case protocol.MsgSSHKeyRemove:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("ssh-key-remove", func() {
					handleSSHKeyRemove(transport, msg)
				})
			}()
		case protocol.MsgDesktopStart:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("desktop-start", func() {
					deskMgr.HandleDesktopStart(transport, msg)
				})
			}()
		case protocol.MsgDesktopData:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("desktop-data", func() {
					deskMgr.HandleDesktopData(msg)
				})
			}()
		case protocol.MsgDesktopClose:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("desktop-close", func() {
					deskMgr.HandleDesktopClose(msg)
				})
			}()
		case protocol.MsgDesktopListDisplays:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("desktop-list-displays", func() {
					handleListDisplays(transport, msg)
				})
			}()
		case protocol.MsgDesktopDiagnose:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("desktop-diagnose", func() {
					handleDesktopDiagnose(transport, msg, deskMgr, webrtcMgr)
				})
			}()
		case protocol.MsgWebRTCStart:
			if webrtcMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("webrtc-start", func() {
						webrtcMgr.HandleWebRTCStart(transport, msg)
					})
				}()
			}
		case protocol.MsgWebRTCOffer:
			if webrtcMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("webrtc-offer", func() {
						webrtcMgr.HandleWebRTCOffer(msg, transport)
					})
				}()
			}
		case protocol.MsgWebRTCICE:
			if webrtcMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("webrtc-ice", func() {
						webrtcMgr.HandleWebRTCICE(msg)
					})
				}()
			}
		case protocol.MsgWebRTCInput:
			if webrtcMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("webrtc-input", func() {
						webrtcMgr.HandleWebRTCInput(msg)
					})
				}()
			}
		case protocol.MsgWebRTCStop:
			if webrtcMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("webrtc-stop", func() {
						webrtcMgr.HandleWebRTCStop(msg, transport)
					})
				}()
			}
		case protocol.MsgWoLSend:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("wol-send", func() {
					system.HandleWoLSend(transport, msg)
				})
			}()
		case protocol.MsgFileList:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-list", func() {
					fileMgr.HandleFileList(transport, msg)
				})
			}()
		case protocol.MsgFileRead:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-read", func() {
					fileMgr.HandleFileRead(transport, msg)
				})
			}()
		case protocol.MsgFileWrite:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-write", func() {
					fileMgr.HandleFileWrite(transport, msg)
				})
			}()
		case protocol.MsgFileMkdir:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-mkdir", func() {
					fileMgr.HandleFileMkdir(transport, msg)
				})
			}()
		case protocol.MsgFileDelete:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-delete", func() {
					fileMgr.HandleFileDelete(transport, msg)
				})
			}()
		case protocol.MsgFileRename:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-rename", func() {
					fileMgr.HandleFileRename(transport, msg)
				})
			}()
		case protocol.MsgFileCopy:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-copy", func() {
					fileMgr.HandleFileCopy(transport, msg)
				})
			}()
		case protocol.MsgFileSearch:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("file-search", func() {
					fileMgr.HandleFileSearch(transport, msg)
				})
			}()
		case protocol.MsgProcessList:
			if processMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("process-list", func() {
						processMgr.HandleProcessList(transport, msg)
					})
				}()
			}
		case protocol.MsgProcessKill:
			if processMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("process-kill", func() {
						processMgr.HandleProcessKill(transport, msg)
					})
				}()
			}
		case protocol.MsgServiceList:
			if serviceMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("service-list", func() {
						serviceMgr.HandleServiceList(transport, msg)
					})
				}()
			}
		case protocol.MsgServiceAction:
			if serviceMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("service-action", func() {
						serviceMgr.HandleServiceAction(transport, msg)
					})
				}()
			}
		case protocol.MsgJournalQuery:
			if journalMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("journal-query", func() {
						journalMgr.HandleJournalQuery(transport, msg)
					})
				}()
			}
		case protocol.MsgDiskList:
			if diskMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("disk-list", func() {
						diskMgr.HandleDiskList(transport, msg)
					})
				}()
			}
		case protocol.MsgNetworkList:
			if networkMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("network-list", func() {
						networkMgr.HandleNetworkList(transport, msg)
					})
				}()
			}
		case protocol.MsgNetworkAction:
			if networkMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("network-action", func() {
						networkMgr.HandleNetworkAction(transport, msg)
					})
				}()
			}
		case protocol.MsgPackageList:
			if packageMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("package-list", func() {
						packageMgr.HandlePackageList(transport, msg)
					})
				}()
			}
		case protocol.MsgPackageAction:
			if packageMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("package-action", func() {
						packageMgr.HandlePackageAction(transport, msg)
					})
				}()
			}
		case protocol.MsgCronList:
			if cronMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("cron-list", func() {
						cronMgr.HandleCronList(transport, msg)
					})
				}()
			}
		case protocol.MsgUsersList:
			if usersMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("users-list", func() {
						usersMgr.HandleUsersList(transport, msg)
					})
				}()
			}
		case protocol.MsgAlertNotify:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("alert-notify", func() {
					handleAlertNotify(msg, runtime)
				})
			}()
		case protocol.MsgEnrollmentChallenge:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("enrollment-challenge", func() {
					handleEnrollmentChallenge(transport, msg, cfg)
				})
			}()
		case protocol.MsgEnrollmentApproved:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("enrollment-approved", func() {
					handleEnrollmentApproved(transport, msg, cfg)
				})
			}()
		case protocol.MsgEnrollmentRejected:
			sem <- struct{}{}
			handlerWG.Add(1)
			go func() {
				defer handlerWG.Done()
				defer func() { <-sem }()
				safeHandler("enrollment-rejected", func() {
					handleEnrollmentRejected(msg)
				})
			}()
		// Clipboard messages.
		case protocol.MsgClipboardGet:
			if clipMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("clipboard-get", func() {
						clipMgr.HandleClipboardGet(transport, msg)
					})
				}()
			}
		case protocol.MsgClipboardSet:
			if clipMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("clipboard-set", func() {
						clipMgr.HandleClipboardSet(transport, msg)
					})
				}()
			}
		// Desktop audio sideband messages.
		case protocol.MsgDesktopAudioStart:
			if audioMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("desktop-audio-start", func() {
						audioMgr.HandleAudioStart(transport, msg)
					})
				}()
			}
		case protocol.MsgDesktopAudioStop:
			if audioMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("desktop-audio-stop", func() {
						audioMgr.HandleAudioStop(msg)
					})
				}()
			}
		// Docker container management messages.
		case protocol.MsgDockerAction:
			if dockerCollector != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-action", func() {
						dockerCollector.HandleDockerAction(transport, msg)
					})
				}()
			}
		case protocol.MsgDockerExecStart:
			if execMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-exec-start", func() {
						execMgr.HandleExecStart(transport, msg)
					})
				}()
			}
		case protocol.MsgDockerExecInput:
			if execMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-exec-input", func() {
						execMgr.HandleExecInput(msg)
					})
				}()
			}
		case protocol.MsgDockerExecResize:
			if execMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-exec-resize", func() {
						execMgr.HandleExecResize(msg)
					})
				}()
			}
		case protocol.MsgDockerExecClose:
			if execMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-exec-close", func() {
						execMgr.HandleExecClose(msg)
					})
				}()
			}
		case protocol.MsgDockerLogsStart:
			if dockerLogMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-logs-start", func() {
						dockerLogMgr.HandleLogsStart(ctx, transport, msg)
					})
				}()
			}
		case protocol.MsgDockerLogsStop:
			if dockerLogMgr != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-logs-stop", func() {
						dockerLogMgr.HandleLogsStop(msg)
					})
				}()
			}
		case protocol.MsgDockerComposeAction:
			if dockerCollector != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("docker-compose-action", func() {
						dockerCollector.HandleComposeAction(transport, msg)
					})
				}()
			}
		case protocol.MsgWebServiceSync:
			if webServiceCollector != nil {
				sem <- struct{}{}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					safeHandler("web-service-sync", func() {
						webServiceCollector.RunCycle(ctx)
					})
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
