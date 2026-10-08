package files

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labtether/protocol"
	"io"
	"log"
)

// HandleFileRead handles a file read request from the hub.
func (fm *Manager) HandleFileRead(transport MessageSender, msg protocol.Message) {
	fm.HandleFileReadContext(context.Background(), transport, msg)
}

// HandleFileReadContext handles a file read request and stops streaming when
// the caller's lifecycle ends. The non-context wrapper is retained for direct
// callers outside the receive loop.
func (fm *Manager) HandleFileReadContext(ctx context.Context, transport MessageSender, msg protocol.Message) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return
	}

	var req protocol.FileReadData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("file: invalid read request: %v", err)
		return
	}

	root, relPath, _, err := fm.OpenRootPath(req.Path)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, err.Error())
		return
	}
	defer root.Close()
	if ctx.Err() != nil {
		return
	}

	f, err := openRootFileForRead(root, relPath)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, err.Error())
		return
	}
	defer f.Close()
	if ctx.Err() != nil {
		return
	}
	info, err := f.Stat()
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, err.Error())
		return
	}
	if info.IsDir() {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, "cannot read a directory")
		return
	}
	if !info.Mode().IsRegular() {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, "cannot read a non-regular file")
		return
	}
	if info.Size() > MaxFileSize {
		_ = fm.sendFileData(transport, req.RequestID, "", 0, true, errFileReadLimitExceeded.Error())
		return
	}

	offset, streamErr := fm.streamFileRead(ctx, transport, req.RequestID, f, MaxFileSize)
	if streamErr != nil {
		switch {
		case errors.Is(streamErr, context.Canceled), errors.Is(streamErr, context.DeadlineExceeded):
			log.Printf("file: read canceled request_id=%s: %v", req.RequestID, streamErr)
		case errors.Is(streamErr, errFileReadSendFailed):
			log.Printf("file: read transport failed request_id=%s: %v", req.RequestID, streamErr)
		default:
			if sendErr := fm.sendFileData(transport, req.RequestID, "", offset, true, streamErr.Error()); sendErr != nil {
				log.Printf("file: failed to send read error request_id=%s: %v", req.RequestID, sendErr)
			}
		}
	}
}

func (fm *Manager) streamFileRead(ctx context.Context, transport MessageSender, requestID string, reader io.Reader, maxBytes int64) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxBytes < 0 {
		return 0, errFileReadLimitExceeded
	}
	buf := make([]byte, FileChunkSize)
	var offset int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		remaining := maxBytes - offset
		readSize := int64(len(buf))
		if remaining < readSize {
			readSize = remaining + 1
		}
		if readSize < 1 {
			readSize = 1
		}

		n, readErr := reader.Read(buf[:int(readSize)])
		if n < 0 || n > int(readSize) {
			return offset, fmt.Errorf("invalid read count %d", n)
		}
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		if n > 0 {
			emptyReads = 0
			if int64(n) > remaining {
				return offset, errFileReadLimitExceeded
			}
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			done := readErr == io.EOF
			if sendErr := fm.sendFileData(transport, requestID, encoded, offset, done, ""); sendErr != nil {
				return offset, fmt.Errorf("%w: %v", errFileReadSendFailed, sendErr)
			}
			offset += int64(n)
			if done {
				return offset, nil
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return offset, io.ErrNoProgress
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return offset, readErr
			}
			// EOF with n==0 -- send final empty done marker.
			if sendErr := fm.sendFileData(transport, requestID, "", offset, true, ""); sendErr != nil {
				return offset, fmt.Errorf("%w: %v", errFileReadSendFailed, sendErr)
			}
			return offset, nil
		}
	}
}

func (fm *Manager) sendFileData(transport MessageSender, requestID, data string, offset int64, done bool, errMsg string) error {
	payload, err := json.Marshal(protocol.FileDataPayload{
		RequestID: requestID,
		Data:      data,
		Offset:    offset,
		Done:      done,
		Error:     errMsg,
	})
	if err != nil {
		return err
	}
	return transport.Send(protocol.Message{
		Type: protocol.MsgFileData,
		ID:   requestID,
		Data: payload,
	})
}
