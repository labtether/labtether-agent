package docker

import (
	"context"
	"encoding/json"
	"log"
	"sync"

	"github.com/labtether/protocol"
)

const maxLogStreams = 5

// dockerLogStream tracks an active log stream for a container.
type dockerLogStream struct {
	sessionID string
	cancel    context.CancelFunc
	done      chan struct{}
}

// dockerLogManager manages container log streams on the agent.
type DockerLogManager struct {
	mu      sync.Mutex
	streams map[string]*dockerLogStream
	client  *dockerClient
}

func NewDockerLogManager(client *dockerClient) *DockerLogManager {
	return &DockerLogManager{
		streams: make(map[string]*dockerLogStream),
		client:  client,
	}
}

func (lm *DockerLogManager) HandleLogsStart(ctx context.Context, transport Transport, msg protocol.Message) {
	if start := lm.PrepareLogsStart(ctx, transport, msg); start != nil {
		start()
	}
}

func (lm *DockerLogManager) PrepareLogsStart(ctx context.Context, transport Transport, msg protocol.Message) func() {
	var req protocol.DockerLogsStartData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("docker-logs: invalid start request: %v", err)
		return nil
	}

	if req.SessionID == "" || req.ContainerID == "" {
		log.Printf("docker-logs: missing session_id or container_id")
		return nil
	}

	lm.mu.Lock()
	if len(lm.streams) >= maxLogStreams {
		lm.mu.Unlock()
		log.Printf("docker-logs: max streams (%d) reached", maxLogStreams)
		return nil
	}
	if _, exists := lm.streams[req.SessionID]; exists {
		lm.mu.Unlock()
		return nil
	}
	if ctx.Err() != nil {
		lm.mu.Unlock()
		return nil
	}

	tail := req.Tail
	if tail <= 0 {
		tail = 100
	}

	ctx, cancel := context.WithCancel(ctx)
	stream := &dockerLogStream{
		sessionID: req.SessionID,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	lm.streams[req.SessionID] = stream
	lm.mu.Unlock()

	return func() {
		go func() {
			defer cancel()
			defer close(stream.done)
			defer func() {
				lm.mu.Lock()
				if lm.streams[req.SessionID] == stream {
					delete(lm.streams, req.SessionID)
				}
				lm.mu.Unlock()
			}()

			if ctx.Err() != nil {
				return
			}
			send := func(streamName, content string) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				lm.mu.Lock()
				current := lm.streams[req.SessionID] == stream
				lm.mu.Unlock()
				if !current {
					return context.Canceled
				}
				data, _ := json.Marshal(protocol.DockerLogsStreamData{SessionID: req.SessionID, Stream: streamName, Data: content})
				return transport.Send(protocol.Message{Type: protocol.MsgDockerLogsStream, ID: req.SessionID, Data: data})
			}
			fail := func(err error) {
				if ctx.Err() != nil {
					return
				}
				log.Printf("docker-logs: session %s failed: %v", req.SessionID, err)
				_ = send("stderr", "[LabTether] Docker log stream failed: "+err.Error())
			}
			tty, err := lm.client.containerLogTTY(ctx, req.ContainerID)
			if err != nil {
				fail(err)
				return
			}
			body, err := lm.client.containerLogs(ctx, req.ContainerID, tail, req.Follow, req.Timestamps)
			if err != nil {
				fail(err)
				return
			}
			defer body.Close()
			if err := streamDockerLogLines(ctx, body, tty, send); err != nil {
				fail(err)
			}

		}()
	}
}

func (lm *DockerLogManager) HandleLogsStop(msg protocol.Message) {
	var req protocol.DockerLogsStopData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return
	}

	lm.mu.Lock()
	stream, ok := lm.streams[req.SessionID]
	if ok {
		delete(lm.streams, req.SessionID)
	}
	lm.mu.Unlock()
	if !ok {
		return
	}

	stream.cancel()
}

func (lm *DockerLogManager) CloseAll() {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for id, stream := range lm.streams {
		stream.cancel()
		delete(lm.streams, id)
	}
}
