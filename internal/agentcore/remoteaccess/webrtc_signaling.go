package remoteaccess

import (
	"context"
	"encoding/json"
	"github.com/labtether/labtether-agent/internal/agentcore/sysconfig"
	"github.com/labtether/protocol"
	"github.com/pion/webrtc/v4"
	"log"
	"math"
	"strings"
	"time"
)

type WebRTCClipboardMessage struct {
	Type   string `json:"type"`
	Format string `json:"format,omitempty"`
	Text   string `json:"text,omitempty"`
	Error  string `json:"error,omitempty"`
}

type WebRTCFileTransferMessage struct {
	Type         string `json:"type"`
	RequestID    string `json:"request_id"`
	Name         string `json:"name,omitempty"`
	Path         string `json:"path,omitempty"`
	Data         string `json:"data,omitempty"`
	Offset       int64  `json:"offset,omitempty"`
	Done         bool   `json:"done,omitempty"`
	BytesWritten int64  `json:"bytes_written,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (wm *WebRTCManager) HandleWebRTCOffer(msg protocol.Message, transport MessageSender) {
	if offer := wm.PrepareWebRTCOffer(msg, transport); offer != nil {
		offer()
	}
}

// Capture the connection owner in receive order; Pion work runs after dispatch.
func (wm *WebRTCManager) PrepareWebRTCOffer(msg protocol.Message, transport MessageSender) func() {
	var offer protocol.WebRTCSDPData
	if err := json.Unmarshal(msg.Data, &offer); err != nil {
		return nil
	}
	if strings.TrimSpace(offer.SessionID) == "" || strings.TrimSpace(offer.SDP) == "" {
		return nil
	}

	wm.Mu.Lock()
	sess, ok := wm.Sessions[offer.SessionID]
	wm.Mu.Unlock()
	if !ok {
		return nil
	}

	return func() {
		if !wm.sessionIsCurrent(offer.SessionID, sess) {
			return
		}

		log.Printf("webrtc: received offer for session=%s", offer.SessionID)
		if err := sess.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer.SDP}); err != nil {
			log.Printf("webrtc: set remote description failed for %s: %v", offer.SessionID, err)
			return
		}

		answer, err := sess.pc.CreateAnswer(nil)
		if err != nil {
			log.Printf("webrtc: create answer failed for %s: %v", offer.SessionID, err)
			return
		}
		if err := sess.pc.SetLocalDescription(answer); err != nil {
			log.Printf("webrtc: set local description failed for %s: %v", offer.SessionID, err)
			return
		}
		log.Printf("webrtc: created answer for session=%s", offer.SessionID)

		answerData, _ := json.Marshal(protocol.WebRTCSDPData{
			SessionID: offer.SessionID,
			Type:      "answer",
			SDP:       answer.SDP,
		})
		wm.sendSessionMessageIfCurrent(
			transport,
			offer.SessionID,
			sess,
			protocol.Message{Type: protocol.MsgWebRTCAnswer, ID: offer.SessionID, Data: answerData},
		)
	}
}

func (wm *WebRTCManager) HandleWebRTCICE(msg protocol.Message) {
	if ice := wm.PrepareWebRTCICE(msg); ice != nil {
		ice()
	}
}

func (wm *WebRTCManager) PrepareWebRTCICE(msg protocol.Message) func() {
	var data protocol.WebRTCICEData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return nil
	}
	if strings.TrimSpace(data.SessionID) == "" || strings.TrimSpace(data.Candidate) == "" {
		return nil
	}

	wm.Mu.Lock()
	sess, ok := wm.Sessions[data.SessionID]
	wm.Mu.Unlock()
	if !ok {
		return nil
	}

	return func() {
		if !wm.sessionIsCurrent(data.SessionID, sess) {
			return
		}

		candidate := webrtc.ICECandidateInit{Candidate: data.Candidate}
		if strings.TrimSpace(data.SDPMid) != "" {
			sdpMid := strings.TrimSpace(data.SDPMid)
			candidate.SDPMid = &sdpMid
		}
		if data.SDPMLineIndex != nil {
			if *data.SDPMLineIndex < 0 || *data.SDPMLineIndex > math.MaxUint16 {
				log.Printf("webrtc: ignoring ICE candidate with invalid m-line index %d for %s", *data.SDPMLineIndex, data.SessionID)
				return
			}
			index := uint16(*data.SDPMLineIndex)
			candidate.SDPMLineIndex = &index
		}
		if err := sess.pc.AddICECandidate(candidate); err != nil {
			log.Printf("webrtc: add ICE candidate failed for %s: %v", data.SessionID, err)
		}
	}
}

func (wm *WebRTCManager) HandleWebRTCInput(msg protocol.Message, transport MessageSender) {
	var data protocol.WebRTCInputData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return
	}
	wm.Mu.Lock()
	sess, ok := wm.Sessions[strings.TrimSpace(data.SessionID)]
	wm.Mu.Unlock()
	if !ok {
		return
	}
	wm.enqueueWebRTCInput(transport, sess, WebRTCInputEvent{
		Type:    strings.TrimSpace(data.Type),
		KeyCode: data.KeyCode,
		Code:    strings.TrimSpace(data.Code),
		Key:     strings.TrimSpace(data.Key),
		X:       data.X,
		Y:       data.Y,
		Button:  data.Button,
		DeltaY:  data.DeltaY,
	})
}

func (wm *WebRTCManager) handleClipboardDataChannelMessage(dc *webrtc.DataChannel, msg webrtc.DataChannelMessage) {
	if dc == nil || !msg.IsString {
		return
	}
	var payload WebRTCClipboardMessage
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return
	}
	reply := WebRTCClipboardMessage{Type: payload.Type, Format: "text"}
	switch strings.TrimSpace(strings.ToLower(payload.Type)) {
	case "get":
		text, _, err := sysconfig.PlatformClipboardRead("text")
		if err != nil {
			reply.Type = "error"
			reply.Error = err.Error()
		} else {
			reply.Type = "data"
			reply.Text = text
		}
	case "set":
		if err := sysconfig.PlatformClipboardWriteText(payload.Text); err != nil {
			reply.Type = "error"
			reply.Error = err.Error()
		} else {
			reply.Type = "ack"
		}
	default:
		return
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return
	}
	if err := dc.SendText(string(raw)); err != nil {
		log.Printf("webrtc: clipboard data channel reply failed: %v", err)
	}
}

func (wm *WebRTCManager) handleFileTransferDataChannelMessage(dc *webrtc.DataChannel, msg webrtc.DataChannelMessage) {
	wm.handleFileTransferDataChannelMessageContext(context.Background(), dc, msg)
}

func (wm *WebRTCManager) handleFileTransferDataChannelMessageContext(ctx context.Context, dc *webrtc.DataChannel, msg webrtc.DataChannelMessage) {
	if ctx.Err() != nil {
		return
	}
	if dc == nil || !msg.IsString || wm.fileMgr == nil {
		return
	}
	var payload WebRTCFileTransferMessage
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return
	}
	reply := WebRTCFileTransferMessage{
		Type:      "ack",
		RequestID: strings.TrimSpace(payload.RequestID),
	}
	if reply.RequestID == "" {
		return
	}
	switch strings.TrimSpace(strings.ToLower(payload.Type)) {
	case "start":
		reply.Type = "ready"
	case "chunk":
		bytesWritten, err := wm.fileMgr.WriteChunkContext(ctx, protocol.FileWriteData{
			RequestID: payload.RequestID,
			Path:      payload.Path,
			Data:      payload.Data,
			Offset:    payload.Offset,
			Done:      payload.Done,
		})
		reply.BytesWritten = bytesWritten
		reply.Done = payload.Done && err == nil
		if err != nil {
			reply.Type = "error"
			reply.Error = err.Error()
		}
	default:
		return
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return
	}
	if err := dc.SendText(string(raw)); err != nil {
		log.Printf("webrtc: file transfer data channel reply failed: %v", err)
	}
}

func SendWebRTCStopped(transport MessageSender, sessionID, reason string) {
	data, _ := json.Marshal(protocol.WebRTCStoppedData{SessionID: sessionID, Reason: reason})
	_ = transport.Send(protocol.Message{Type: protocol.MsgWebRTCStopped, ID: sessionID, Data: data})
}

func ICECandidateSendDelay(candidate string) time.Duration {
	switch ParseICECandidateType(candidate) {
	case "relay":
		return 300 * time.Millisecond
	case "srflx", "prflx":
		return 150 * time.Millisecond
	default:
		return 0
	}
}

func ParseICECandidateType(candidate string) string {
	parts := strings.Fields(strings.TrimSpace(candidate))
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "typ" {
			return strings.ToLower(strings.TrimSpace(parts[i+1]))
		}
	}
	return ""
}

func ValueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
