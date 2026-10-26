package sysconfig

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/labtether/protocol"
)

var ClipboardRead = PlatformClipboardRead
var ClipboardWriteText = PlatformClipboardWriteText
var ClipboardWriteImage = PlatformClipboardWriteImage

// ClipboardManager handles clipboard read/write requests from the hub.
// Clipboard operations are stateless — each request executes immediately
// using platform-specific tooling (pbcopy/pbpaste, xclip/xsel, PowerShell).
type ClipboardManager struct{}

func NewClipboardManager() *ClipboardManager { return &ClipboardManager{} }

// CloseAll is a no-op for ClipboardManager — clipboard requests are stateless
// and require no cleanup.
func (cm *ClipboardManager) CloseAll() {}

// HandleClipboardGet reads the OS clipboard and sends the contents back to the hub.
func (cm *ClipboardManager) HandleClipboardGet(transport MessageSender, msg protocol.Message) {
	var req protocol.ClipboardGetData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("clipboard: invalid get request: %v", err)
		return
	}

	format, err := normalizeClipboardFormat(req.Format)
	var text, imgBase64 string
	if err == nil {
		text, imgBase64, err = ClipboardRead(format)
	}

	resp := protocol.ClipboardDataPayload{
		RequestID: req.RequestID,
	}
	if err != nil {
		resp.Error = err.Error()
	} else if format == "text" {
		resp.Format = "text"
		resp.Text = text
	} else {
		resp.Format = "image/png"
		resp.Data = imgBase64
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("clipboard: failed to marshal response: %v", err)
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgClipboardData,
		Data: data,
	})
}

// HandleClipboardSet writes content to the OS clipboard and sends an ack back.
func (cm *ClipboardManager) HandleClipboardSet(transport MessageSender, msg protocol.Message) {
	var req protocol.ClipboardSetData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("clipboard: invalid set request: %v", err)
		return
	}

	format, writeErr := normalizeClipboardFormat(req.Format)
	switch format {
	case "text":
		writeErr = ClipboardWriteText(req.Text)
	case "image/png":
		writeErr = ClipboardWriteImage(req.Data)
	}

	ack := protocol.ClipboardSetAckData{
		RequestID: req.RequestID,
		OK:        writeErr == nil,
	}
	if writeErr != nil {
		ack.Error = writeErr.Error()
	}

	data, err := json.Marshal(ack)
	if err != nil {
		log.Printf("clipboard: failed to marshal ack: %v", err)
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgClipboardSetAck,
		Data: data,
	})
}

func normalizeClipboardFormat(format string) (string, error) {
	switch format {
	case "", "text", "text/plain":
		return "text", nil
	case "image", "image/png":
		return "image/png", nil
	default:
		return "", fmt.Errorf("unsupported clipboard format %q", format)
	}
}
