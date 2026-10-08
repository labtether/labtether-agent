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
)

func startFileReadHandler(ctx context.Context, transport files.MessageSender, fileMgr *files.Manager, msg protocol.Message, sem chan struct{}, handlerWG *sync.WaitGroup) bool {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return false
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

func enqueueOrderedFileWrite(ctx context.Context, transport files.MessageSender, messages chan<- protocol.Message, msg protocol.Message) bool {
	messageSize := len(msg.Type) + len(msg.ID) + len(msg.Data)
	if messageSize > files.MaxFileWriteQueuedMessageSize {
		requestID := strings.TrimSpace(msg.ID)
		if len(requestID) > 256 {
			requestID = requestID[:256]
		}
		errMessage := fmt.Sprintf("file.write message exceeds %d byte limit", files.MaxFileWriteQueuedMessageSize)
		log.Printf(
			"agentws: rejected file.write message for request %q: %d bytes exceeds %d byte limit",
			requestID,
			messageSize,
			files.MaxFileWriteQueuedMessageSize,
		)
		data, err := json.Marshal(protocol.FileWrittenData{RequestID: requestID, Error: errMessage})
		if err == nil {
			_ = transport.Send(protocol.Message{Type: protocol.MsgFileWritten, ID: requestID, Data: data})
		}
		return true
	}
	select {
	case messages <- msg:
		return true
	case <-ctx.Done():
		return false
	}
}

func runOrderedFileWriteWorker(ctx context.Context, transport *wsTransport, fileMgr *files.Manager, messages <-chan protocol.Message) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-messages:
			if !ok {
				return
			}
			safeHandler("file-write", func() {
				fileMgr.HandleFileWrite(transport, msg)
			})
		}
	}
}
