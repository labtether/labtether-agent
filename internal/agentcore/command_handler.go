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
	// goroutine growth under load. Session input owns separate bounded writers.
	const maxConcurrentHandlers = 20
	sem := make(chan struct{}, maxConcurrentHandlers)
	sessionStarts := make(chan struct{}, 30)
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

	// Upload chunks share a request ID and offsets, so they must be applied in
	// WebSocket delivery order. Dispatching each file.write in an independent
	// goroutine lets a later EOF marker overtake the data chunk and corrupts the
	// upload state. A bounded worker preserves ordering and applies natural
	// backpressure without serializing unrelated command handlers.
	const maxQueuedFileWriteMessages = 64
	fileWriteMessages := make(chan orderedFileWrite, maxQueuedFileWriteMessages)
	handlerWG.Add(1)
	go func() {
		defer handlerWG.Done()
		runOrderedFileWriteWorker(ctx, fileMgr, fileWriteMessages)
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

		msg, enrollmentPending, sourceConn, err := transport.receiveWithConnection()
		if err != nil {
			if sourceConn != nil && transport.socketOpen() {
				if websocket.IsCloseError(err, websocket.CloseGoingAway) {
					log.Printf("agentws: hub shutting down, will reconnect immediately")
				} else {
					log.Printf("agentws: receive error: %v", err)
				}
				transport.markDisconnectedIfCurrent(sourceConn)
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

		sender := transport.senderForConnection(sourceConn)
		if sender == nil {
			continue
		}
		messageConfig := runtimeConfigWithCurrentIdentity(cfg, transport)
		dispatch := func(name string, handle func()) { launchConnectionHandler(sender, sem, &handlerWG, name, handle) }

		if dispatchSessionMessage(transport, sourceConn, msg, termMgr, deskMgr, execMgr, webrtcMgr, audioMgr, dockerLogMgr, sessionStarts, &handlerWG) {
			continue
		}

		if dispatchNodeMessage(msg, sender, dispatch, processMgr, serviceMgr, journalMgr, diskMgr, networkMgr, packageMgr, cronMgr, usersMgr) {
			continue
		}

		switch msg.Type {
		case protocol.MsgCommandRequest:
			dispatch("command-request", func() {
				handleCommandRequest(sender, msg, messageConfig)
			})
		case msgPowerAction:
			select {
			case powerSem <- struct{}{}:
				select {
				case sem <- struct{}{}:
				case <-sender.Context().Done():
					<-powerSem
					continue
				default:
					<-powerSem
					sender.Close()
					continue
				}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					defer func() { <-powerSem }()
					safeHandler("power-action", func() {
						handlePowerAction(sender.Context(), sender, msg, powerRuntime)
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
				_ = sender.Send(protocol.Message{Type: protocol.MsgPong})
			})
		case protocol.MsgConfigUpdate:
			dispatch("config-update", func() {
				handleConfigUpdate(sender, msg, runtime)
			})
		case protocol.MsgAgentSettingsApply:
			dispatch("agent-settings-apply", func() {
				handleAgentSettingsApply(sender, msg, runtime)
			})
		case protocol.MsgUpdateRequest:
			dispatch("update-request", func() {
				handleUpdateRequest(sender, msg, messageConfig)
			})
		case protocol.MsgTerminalProbe:
			dispatch("terminal-probe", func() {
				termMgr.HandleTerminalProbe(transport)
			})
		case protocol.MsgTerminalTmuxKill:
			dispatch("terminal-tmux-kill", func() {
				termMgr.HandleTerminalTmuxKill(sender, msg)
			})
		case protocol.MsgSSHKeyInstall:
			dispatch("ssh-key-install", func() {
				handleSSHKeyInstall(sender, msg)
			})
		case protocol.MsgSSHKeyRemove:
			dispatch("ssh-key-remove", func() {
				handleSSHKeyRemove(sender, msg)
			})
		case protocol.MsgDesktopListDisplays:
			dispatch("desktop-list-displays", func() {
				handleListDisplays(sender, msg)
			})
		case protocol.MsgDesktopDiagnose:
			dispatch("desktop-diagnose", func() {
				handleDesktopDiagnose(sender, msg, deskMgr, webrtcMgr)
			})
		case protocol.MsgWoLSend:
			dispatch("wol-send", func() {
				system.HandleWoLSend(sender, msg)
			})
		case protocol.MsgFileList:
			dispatch("file-list", func() {
				fileMgr.HandleFileList(sender, msg)
			})
		case protocol.MsgFileRead:
			if !startFileReadHandler(sender.Context(), sender, fileMgr, msg, sem, &handlerWG) {
				continue
			}
		case protocol.MsgFileWrite:
			if !enqueueOrderedFileWrite(sender.Context(), sender, fileWriteMessages, msg) {
				continue
			}
		case protocol.MsgFileMkdir:
			dispatch("file-mkdir", func() {
				fileMgr.HandleFileMkdir(sender, msg)
			})
		case protocol.MsgFileDelete:
			dispatch("file-delete", func() {
				fileMgr.HandleFileDelete(sender, msg)
			})
		case protocol.MsgFileRename:
			dispatch("file-rename", func() {
				fileMgr.HandleFileRename(sender, msg)
			})
		case protocol.MsgFileCopy:
			dispatch("file-copy", func() {
				fileMgr.HandleFileCopyContext(sender.Context(), sender, msg)
			})
		case protocol.MsgFileSearch:
			dispatch("file-search", func() {
				fileMgr.HandleFileSearch(sender, msg)
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
					clipMgr.HandleClipboardGet(sender, msg)
				})
			}
		case protocol.MsgClipboardSet:
			if clipMgr != nil {
				dispatch("clipboard-set", func() {
					clipMgr.HandleClipboardSet(sender, msg)
				})
			}
		// Desktop audio sideband messages.
		case protocol.MsgDockerEndpointTest:
			select {
			case dockerEndpointTestSem <- struct{}{}:
				select {
				case sem <- struct{}{}:
				case <-sender.Context().Done():
					<-dockerEndpointTestSem
					continue
				default:
					<-dockerEndpointTestSem
					sender.Close()
					continue
				}
				handlerWG.Add(1)
				go func() {
					defer handlerWG.Done()
					defer func() { <-sem }()
					defer func() { <-dockerEndpointTestSem }()
					safeHandler("docker-endpoint-test", func() {
						handleDockerEndpointTest(sender.Context(), sender, msg)
					})
				}()
			default:
				sendDockerEndpointTestBusy(sender, msg)
			}
		case protocol.MsgDockerAction:
			if dockerCollector != nil {
				dispatch("docker-action", func() {
					dockerCollector.HandleDockerAction(sender, msg)
				})
			}
		case protocol.MsgDockerComposeAction:
			if dockerCollector != nil {
				dispatch("docker-compose-action", func() {
					dockerCollector.HandleComposeAction(sender, msg)
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
