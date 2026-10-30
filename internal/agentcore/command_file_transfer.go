package agentcore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
	"log"
	"strings"
	"sync"
	"time"
)

func startFileReadHandler(ctx context.Context, transport files.MessageSender, fileMgr *files.Manager, msg protocol.Message, sem chan struct{}, handlerWG *sync.WaitGroup) bool {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return false
	default:
		if owner, ok := transport.(interface{ Close() }); ok {
			owner.Close()
		}
		return true
	}

	handlerWG.Add(1)
	go func() {
		defer handlerWG.Done()
		defer func() { <-sem }()
		safeHandler("file-read", func() {
			fileMgr.HandleFileReadContext(ctx, transport, msg)
		})
	}()
	return true
}

type orderedFileWrite struct {
	ctx       context.Context
	transport files.MessageSender
	message   protocol.Message
	requestID string
}

// fileWriteQueueWait bounds how long one upload chunk may hold the socket
// read loop while the ordered writer is behind. While it waits, the agent
// reads nothing from the Hub, so TCP flow control slows the Hub's sender.
// It must stay below the Hub's 10 s per-message write deadline
// (agentmgr.AgentWriteDeadline), or the Hub drops the connection.
const fileWriteQueueWait = 8 * time.Second

// maxFailedUploadIDs bounds the remembered failed uploads. Forgetting one only
// lets a later chunk reach the writer, which refuses it as an offset mismatch.
const maxFailedUploadIDs = 128

// fileWriteQueue applies upload chunks in delivery order. The socket read loop
// is the only caller of enqueue; the worker goroutine runs run.
type fileWriteQueue struct {
	messages chan orderedFileWrite
	wait     time.Duration
	mu       sync.Mutex
	failed   map[string]struct{}
}

func newFileWriteQueue(capacity int, wait time.Duration) *fileWriteQueue {
	return &fileWriteQueue{messages: make(chan orderedFileWrite, capacity), wait: wait, failed: map[string]struct{}{}}
}

// enqueue returns false only when ctx ends. A full queue blocks the read loop
// for at most q.wait. If the writer takes no chunk in that time, this upload
// fails with a file.written error and its later chunks are dropped; the
// connection and other uploads continue.
func (q *fileWriteQueue) enqueue(ctx context.Context, transport files.MessageSender, msg protocol.Message) bool {
	messageSize := len(msg.Type) + len(msg.ID) + len(msg.Data)
	if messageSize > files.MaxFileWriteQueuedMessageSize {
		requestID := boundedUploadRequestID(msg.ID)
		log.Printf(
			"agentws: rejected file.write message for request %q: %d bytes exceeds %d byte limit",
			requestID,
			messageSize,
			files.MaxFileWriteQueuedMessageSize,
		)
		sendFileWriteFailure(transport, requestID, fmt.Sprintf("file.write message exceeds %d byte limit", files.MaxFileWriteQueuedMessageSize))
		return true
	}
	item := orderedFileWrite{ctx: ctx, transport: transport, message: msg, requestID: uploadRequestID(msg)}
	if q.isFailed(item.requestID) {
		return true
	}
	select {
	case q.messages <- item:
		return true
	case <-ctx.Done():
		return false
	default:
	}
	timer := time.NewTimer(q.wait)
	defer timer.Stop()
	select {
	case q.messages <- item:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
	}
	q.markFailed(item.requestID)
	log.Printf("agentws: upload %q failed: the file writer took no data for %s", boundedUploadRequestID(item.requestID), q.wait)
	sendFileWriteFailure(transport, boundedUploadRequestID(item.requestID),
		fmt.Sprintf("upload failed: writing the file on this device made no progress for %s", q.wait))
	return true
}

// run applies queued chunks. Chunks of an upload that enqueue gave up on are
// skipped, and its temporary file is removed.
func (q *fileWriteQueue) run(ctx context.Context, fileMgr *files.Manager) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-q.messages:
			if !ok {
				return
			}
			if q.isFailed(msg.requestID) {
				fileMgr.AbortWrite(msg.requestID)
				continue
			}
			safeHandler("file-write", func() {
				if msg.ctx.Err() == nil {
					fileMgr.HandleFileWriteContext(msg.ctx, msg.transport, msg.message)
				}
			})
		}
	}
}

func (q *fileWriteQueue) isFailed(requestID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, failed := q.failed[requestID]
	return failed && requestID != ""
}

func (q *fileWriteQueue) markFailed(requestID string) {
	if requestID == "" {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.failed) >= maxFailedUploadIDs {
		clear(q.failed)
	}
	q.failed[requestID] = struct{}{}
}

// uploadRequestID returns the upload's request ID. The Hub sends it as the
// message ID; the chunk body is decoded only when that is missing.
func uploadRequestID(msg protocol.Message) string {
	if id := strings.TrimSpace(msg.ID); id != "" {
		return id
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(msg.Data, &body)
	return strings.TrimSpace(body.RequestID)
}

func boundedUploadRequestID(raw string) string {
	requestID := strings.TrimSpace(raw)
	if len(requestID) > 256 {
		requestID = requestID[:256]
	}
	return requestID
}

func sendFileWriteFailure(transport files.MessageSender, requestID, errMessage string) {
	data, err := json.Marshal(protocol.FileWrittenData{RequestID: requestID, Error: errMessage})
	if err == nil {
		_ = transport.Send(protocol.Message{Type: protocol.MsgFileWritten, ID: requestID, Data: data})
	}
}
