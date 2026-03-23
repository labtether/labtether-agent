package system

import (
	"encoding/json"
	"log"

	"github.com/labtether/labtether-agent/internal/wol"
	"github.com/labtether/protocol"
)

// WoLSendFn is the function used to send Wake-on-LAN packets.
// It can be overridden in tests.
var WoLSendFn = wol.Send

// HandleWoLSend handles a Wake-on-LAN send request from the hub.
func HandleWoLSend(transport MessageSender, msg protocol.Message) {
	var req protocol.WoLSendData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("wol: invalid request payload: %v", err)
		return
	}

	result := protocol.WoLResultData{
		RequestID: req.RequestID,
		MAC:       req.MAC,
		OK:        false,
	}

	mac, err := wol.ParseMAC(req.MAC)
	if err != nil {
		result.Error = err.Error()
		sendWoLResult(transport, result)
		return
	}

	broadcast := req.Broadcast
	if broadcast == "" {
		broadcast = "255.255.255.255:9"
	}
	if err := WoLSendFn(mac, broadcast); err != nil {
		result.Error = err.Error()
		sendWoLResult(transport, result)
		return
	}

	result.OK = true
	sendWoLResult(transport, result)
	log.Printf("wol: sent magic packet for %s via %s", req.MAC, broadcast)
}

func sendWoLResult(transport MessageSender, result protocol.WoLResultData) {
	data, err := json.Marshal(result)
	if err != nil {
		log.Printf("wol: marshal result failed: %v", err)
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgWoLResult,
		ID:   result.RequestID,
		Data: data,
	})
}
