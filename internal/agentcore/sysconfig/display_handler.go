package sysconfig

import (
	"encoding/json"
	"log"

	"github.com/labtether/protocol"
)

var PlatformListDisplaysFn = PlatformListDisplays

func HandleListDisplays(transport MessageSender, msg protocol.Message) {
	var req struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(msg.Data, &req)

	displays, err := PlatformListDisplaysFn()
	resp := protocol.DisplayListData{
		RequestID: req.RequestID,
		Displays:  displays,
	}
	if err != nil {
		resp.Error = err.Error()
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("display: marshal response failed: %v", err)
		return
	}
	_ = transport.Send(protocol.Message{
		Type: protocol.MsgDesktopDisplays,
		ID:   req.RequestID,
		Data: data,
	})
}
