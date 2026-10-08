package agentcore

import (
	"context"
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/labtether-agent/internal/agentcore/remoteaccess"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
	"log"
	"sync"
	"time"
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
	// Host power transitions are serialized independently of the general
	// handler pool so duplicate requests cannot race each other.
	powerSem := make(chan struct{}, 1)
	// Docker endpoint probes are collector-independent but serialized so a
	// hostile or buggy Hub cannot create an unbounded set of dial attempts.
	dockerEndpointTestSem := make(chan struct{}, 1)
	powerRuntime := newPlatformPowerBackend()

	// handlerWG tracks all in-flight handler goroutines so receiveLoop can
	// drain them gracefully on disconnect/shutdown.
	var handlerWG sync.WaitGroup

	// All ordinary handlers share the same concurrency and panic boundary.
	dispatch := func(name string, handle func()) {
		sem <- struct{}{}
		handlerWG.Add(1)
		go func() {
			defer handlerWG.Done()
			defer func() { <-sem }()
			safeHandler(name, handle)
		}()
	}

	// Upload chunks share a request ID and offsets, so they must be applied in
	// WebSocket delivery order. Dispatching each file.write in an independent
	// goroutine lets a later EOF marker overtake the data chunk and corrupts the
	// upload state. A bounded worker preserves ordering and applies natural
	// backpressure without serializing unrelated command handlers.
	const maxQueuedFileWriteMessages = 64
	fileWriteMessages := make(chan protocol.Message, maxQueuedFileWriteMessages)
	handlerWG.Add(1)
	go func() {
		defer handlerWG.Done()
		runOrderedFileWriteWorker(ctx, transport, fileMgr, fileWriteMessages)
	}()

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

		// Pending-enrollment sockets are deliberately not product-ready, but the
		// receive loop must keep reading them so it can process the Hub challenge
		// and approval/rejection control messages.
		if !transport.socketOpen() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}

		msg, enrollmentPending, err := transport.receiveWithEnrollmentState()
		if err != nil {
			if transport.socketOpen() {
				if websocket.IsCloseError(err, websocket.CloseGoingAway) {
					log.Printf("agentws: hub shutting down, will reconnect immediately")
				} else {
					log.Printf("agentws: receive error: %v", err)
				}
				transport.markDisconnected()
			}
			continue
		}
		if !inboundMessageAllowed(enrollmentPending, msg.Type) {
			log.Printf("agentws: ignored inbound %q on pending enrollment socket", msg.Type)
			continue
		}
		if required := requiredCapabilitiesForMessage(msg.Type); len(required) > 0 {
			currentBearer := transport.identitySource().Snapshot().BearerToken
			if checked, allowed := remoteaccess.TokenAllowsAnyCapability(currentBearer, required...); checked && !allowed {
				log.Printf("agentws: rejected %s: token lacks required capability", msg.Type)
				if msg.Type == msgPowerAction {
					sendPowerRejectionForMessage(
						transport,
						msg,
						powerResultCodeCapabilityDenied,
						"agent token does not allow power actions",
					)
				}
				continue
			}
		}

		if dispatchNodeMessage(msg, transport, dispatch, processMgr, serviceMgr, journalMgr, diskMgr, networkMgr, packageMgr, cronMgr, usersMgr) {
			continue
		}

		switch msg.Type {
		case protocol.MsgCommandRequest:
			dispatch("command-request", func() {
				handleCommandRequest(transport, msg, runtimeConfigWithCurrentIdentity(cfg, transport))
			})
		case msgPowerAction:
			select {
			case powerSem <- struct{}{}:
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					<-powerSem
					return
				}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					defer func() { <-powerSem }()
					safeHandler("power-action", func() {
						handlePowerAction(ctx, transport, msg, powerRuntime)
					})
				}()
			default:
				sendPowerRejectionForMessage(
					transport,
					msg,
					powerResultCodeBusy,
					"another power action is already in progress",
				)
			}
		case protocol.MsgPing:
			dispatch("ping", func() {
				_ = transport.Send(protocol.Message{Type: protocol.MsgPong})
			})
		case protocol.MsgConfigUpdate:
			dispatch("config-update", func() {
				handleConfigUpdate(transport, msg, runtime)
			})
		case protocol.MsgAgentSettingsApply:
			dispatch("agent-settings-apply", func() {
				handleAgentSettingsApply(transport, msg, runtime)
			})
		case protocol.MsgUpdateRequest:
			dispatch("update-request", func() {
				handleUpdateRequest(transport, msg, runtimeConfigWithCurrentIdentity(cfg, transport))
			})
		case protocol.MsgTerminalProbe:
			dispatch("terminal-probe", func() {
				termMgr.HandleTerminalProbe(transport)
			})
		case protocol.MsgTerminalStart:
			dispatch("terminal-start", func() {
				termMgr.HandleTerminalStart(transport, msg)
			})
		case protocol.MsgTerminalData:
			dispatch("terminal-data", func() {
				termMgr.HandleTerminalData(msg)
			})
		case protocol.MsgTerminalResize:
			dispatch("terminal-resize", func() {
				termMgr.HandleTerminalResize(msg)
			})
		case protocol.MsgTerminalTmuxKill:
			dispatch("terminal-tmux-kill", func() {
				termMgr.HandleTerminalTmuxKill(transport, msg)
			})
		case protocol.MsgTerminalClose:
			dispatch("terminal-close", func() {
				termMgr.HandleTerminalClose(msg)
			})
		case protocol.MsgSSHKeyInstall:
			dispatch("ssh-key-install", func() {
				handleSSHKeyInstall(transport, msg)
			})
		case protocol.MsgSSHKeyRemove:
			dispatch("ssh-key-remove", func() {
				handleSSHKeyRemove(transport, msg)
			})
		case protocol.MsgDesktopStart:
			dispatch("desktop-start", func() {
				deskMgr.HandleDesktopStart(transport, msg)
			})
		case protocol.MsgDesktopData:
			dispatch("desktop-data", func() {
				deskMgr.HandleDesktopData(msg)
			})
		case protocol.MsgDesktopClose:
			dispatch("desktop-close", func() {
				deskMgr.HandleDesktopClose(msg)
			})
		case protocol.MsgDesktopListDisplays:
			dispatch("desktop-list-displays", func() {
				handleListDisplays(transport, msg)
			})
		case protocol.MsgDesktopDiagnose:
			dispatch("desktop-diagnose", func() {
				handleDesktopDiagnose(transport, msg, deskMgr, webrtcMgr)
			})
		case protocol.MsgWebRTCStart:
			if webrtcMgr != nil {
				dispatch("webrtc-start", func() {
					webrtcMgr.HandleWebRTCStart(transport, msg)
				})
			}
		case protocol.MsgWebRTCOffer:
			if webrtcMgr != nil {
				dispatch("webrtc-offer", func() {
					webrtcMgr.HandleWebRTCOffer(msg, transport)
				})
			}
		case protocol.MsgWebRTCICE:
			if webrtcMgr != nil {
				dispatch("webrtc-ice", func() {
					webrtcMgr.HandleWebRTCICE(msg)
				})
			}
		case protocol.MsgWebRTCInput:
			if webrtcMgr != nil {
				dispatch("webrtc-input", func() {
					webrtcMgr.HandleWebRTCInput(msg)
				})
			}
		case protocol.MsgWebRTCStop:
			if webrtcMgr != nil {
				dispatch("webrtc-stop", func() {
					webrtcMgr.HandleWebRTCStop(msg, transport)
				})
			}
		case protocol.MsgWoLSend:
			dispatch("wol-send", func() {
				system.HandleWoLSend(transport, msg)
			})
		case protocol.MsgFileList:
			dispatch("file-list", func() {
				fileMgr.HandleFileList(transport, msg)
			})
		case protocol.MsgFileRead:
			if !startFileReadHandler(ctx, transport, fileMgr, msg, sem, &handlerWG) {
				return
			}
		case protocol.MsgFileWrite:
			if !enqueueOrderedFileWrite(ctx, transport, fileWriteMessages, msg) {
				return
			}
		case protocol.MsgFileMkdir:
			dispatch("file-mkdir", func() {
				fileMgr.HandleFileMkdir(transport, msg)
			})
		case protocol.MsgFileDelete:
			dispatch("file-delete", func() {
				fileMgr.HandleFileDelete(transport, msg)
			})
		case protocol.MsgFileRename:
			dispatch("file-rename", func() {
				fileMgr.HandleFileRename(transport, msg)
			})
		case protocol.MsgFileCopy:
			dispatch("file-copy", func() {
				fileMgr.HandleFileCopyContext(ctx, transport, msg)
			})
		case protocol.MsgFileSearch:
			dispatch("file-search", func() {
				fileMgr.HandleFileSearch(transport, msg)
			})
		case protocol.MsgAlertNotify:
			dispatch("alert-notify", func() {
				handleAlertNotify(msg, runtime)
			})
		case protocol.MsgEnrollmentChallenge:
			dispatch("enrollment-challenge", func() {
				handleEnrollmentChallenge(transport, msg, cfg)
			})
		case protocol.MsgEnrollmentApproved:
			dispatch("enrollment-approved", func() {
				handleEnrollmentApproved(transport, msg, cfg)
			})
		case protocol.MsgEnrollmentRejected:
			dispatch("enrollment-rejected", func() {
				handleEnrollmentRejected(msg)
			})
		// Clipboard messages.
		case protocol.MsgClipboardGet:
			if clipMgr != nil {
				dispatch("clipboard-get", func() {
					clipMgr.HandleClipboardGet(transport, msg)
				})
			}
		case protocol.MsgClipboardSet:
			if clipMgr != nil {
				dispatch("clipboard-set", func() {
					clipMgr.HandleClipboardSet(transport, msg)
				})
			}
		// Desktop audio sideband messages.
		case protocol.MsgDesktopAudioStart:
			if audioMgr != nil {
				dispatch("desktop-audio-start", func() {
					audioMgr.HandleAudioStart(transport, msg)
				})
			}
		case protocol.MsgDesktopAudioStop:
			if audioMgr != nil {
				dispatch("desktop-audio-stop", func() {
					audioMgr.HandleAudioStop(transport, msg)
				})
			}
		// Docker container management messages.
		case protocol.MsgDockerEndpointTest:
			select {
			case dockerEndpointTestSem <- struct{}{}:
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					<-dockerEndpointTestSem
					return
				}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					defer func() { <-dockerEndpointTestSem }()
					safeHandler("docker-endpoint-test", func() {
						handleDockerEndpointTest(ctx, transport, msg)
					})
				}()
			default:
				sendDockerEndpointTestBusy(transport, msg)
			}
		case protocol.MsgDockerAction:
			if dockerCollector != nil {
				dispatch("docker-action", func() {
					dockerCollector.HandleDockerAction(transport, msg)
				})
			}
		case protocol.MsgDockerExecStart:
			if execMgr != nil {
				dispatch("docker-exec-start", func() {
					execMgr.HandleExecStart(transport, msg)
				})
			}
		case protocol.MsgDockerExecInput:
			if execMgr != nil {
				dispatch("docker-exec-input", func() {
					execMgr.HandleExecInput(msg)
				})
			}
		case protocol.MsgDockerExecResize:
			if execMgr != nil {
				dispatch("docker-exec-resize", func() {
					execMgr.HandleExecResize(msg)
				})
			}
		case protocol.MsgDockerExecClose:
			if execMgr != nil {
				dispatch("docker-exec-close", func() {
					execMgr.HandleExecClose(msg)
				})
			}
		case protocol.MsgDockerLogsStart:
			if dockerLogMgr != nil {
				dispatch("docker-logs-start", func() {
					dockerLogMgr.HandleLogsStart(ctx, transport, msg)
				})
			}
		case protocol.MsgDockerLogsStop:
			if dockerLogMgr != nil {
				dispatch("docker-logs-stop", func() {
					dockerLogMgr.HandleLogsStop(msg)
				})
			}
		case protocol.MsgDockerComposeAction:
			if dockerCollector != nil {
				dispatch("docker-compose-action", func() {
					dockerCollector.HandleComposeAction(transport, msg)
				})
			}
		case protocol.MsgWebServiceSync:
			if webServiceCollector != nil {
				dispatch("web-service-sync", func() {
					webServiceCollector.RunCycle(ctx)
				})
			}
		default:
			log.Printf("agentws: unknown message type from hub: %s", msg.Type)
		}
	}
}

func runtimeConfigWithCurrentIdentity(cfg RuntimeConfig, transport *wsTransport) RuntimeConfig {
	if transport == nil {
		return cfg
	}
	identity := transport.identitySource().Snapshot()
	cfg.APIToken = identity.BearerToken
	cfg.AssetID = identity.AssetID
	cfg.WSBaseURL = identity.WSBaseURL
	cfg.APIBaseURL = identity.APIBaseURL
	return cfg
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
	assetID := transport.AssetID()
	if assetID == "" {
		// Compatibility for isolated transport tests. Production transports are
		// always wired to the shared runtime identity source.
		assetID = sample.AssetID
	}
	td := protocol.TelemetryData{
		AssetID:          assetID,
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
