package remoteaccess

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/labtether/protocol"
)

type webRTCStartSender struct{ ctx context.Context }

func (s webRTCStartSender) Context() context.Context    { return s.ctx }
func (s webRTCStartSender) Send(protocol.Message) error { return nil }

func TestWebRTCPreparedStartCannotOutliveSocketOrCloseAll(t *testing.T) {
	for _, stop := range []string{"socket", "close-all"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := NewWebRTCManager(protocol.WebRTCCapabilitiesData{Available: true}, nil, nil, nil)
			raw, _ := json.Marshal(protocol.WebRTCSessionData{SessionID: "old"})
			start := manager.PrepareWebRTCStart(webRTCStartSender{ctx}, protocol.Message{Data: raw})
			if start == nil || len(manager.pending) != 1 {
				t.Fatal("start was not synchronously reserved")
			}
			if stop == "socket" {
				cancel()
			} else {
				manager.CloseAll()
			}
			original := DetectDesktopSessionFn
			DetectDesktopSessionFn = func() DesktopSessionInfo {
				t.Error("canceled prepared start reached backend detection")
				return DesktopSessionInfo{}
			}
			defer func() { DetectDesktopSessionFn = original }()
			start()
			if len(manager.pending) != 0 || len(manager.Sessions) != 0 {
				t.Fatal("canceled prepared start retained an owner")
			}
		})
	}
}

func TestWebRTCPreparedStopCannotCloseReplacement(t *testing.T) {
	manager := NewWebRTCManager(protocol.WebRTCCapabilitiesData{}, nil, nil, nil)
	old := &WebRTCSession{sessionID: "same", done: make(chan struct{})}
	manager.Sessions[old.sessionID] = old
	raw, _ := json.Marshal(protocol.WebRTCStoppedData{SessionID: old.sessionID})
	stop := manager.PrepareWebRTCStop(protocol.Message{Data: raw}, webRTCStartSender{context.Background()})
	if stop == nil || manager.PrepareWebRTCStop(protocol.Message{Data: raw}, webRTCStartSender{context.Background()}) != nil {
		t.Fatal("stop did not claim exactly one owner")
	}
	replacement := &WebRTCSession{sessionID: old.sessionID, done: make(chan struct{})}
	manager.Sessions[old.sessionID] = replacement
	stop()
	select {
	case <-old.done:
	default:
		t.Fatal("captured owner was not closed")
	}
	select {
	case <-replacement.done:
		t.Fatal("delayed stop closed replacement")
	default:
	}
	if manager.Sessions[old.sessionID] != replacement {
		t.Fatal("delayed stop removed replacement")
	}
	manager.CloseAll()
}

func TestWebRTCPreparedSignalingCannotReachReplacement(t *testing.T) {
	manager := NewWebRTCManager(protocol.WebRTCCapabilitiesData{}, nil, nil, nil)
	old := &WebRTCSession{sessionID: "same", done: make(chan struct{})}
	manager.Sessions[old.sessionID] = old
	offerData, _ := json.Marshal(protocol.WebRTCSDPData{SessionID: "same", SDP: "queued offer"})
	iceData, _ := json.Marshal(protocol.WebRTCICEData{SessionID: "same", Candidate: "queued candidate"})
	offer := manager.PrepareWebRTCOffer(protocol.Message{Data: offerData}, webRTCStartSender{context.Background()})
	ice := manager.PrepareWebRTCICE(protocol.Message{Data: iceData})
	if offer == nil || ice == nil {
		t.Fatal("signaling did not capture the current owner")
	}
	// Neither owner has a Pion connection: entering backend work for a stale
	// prepared message would panic. Preparation itself must perform no I/O.
	replacement := &WebRTCSession{sessionID: "same", done: make(chan struct{})}
	manager.Sessions[old.sessionID] = replacement
	offer()
	ice()
	if manager.Sessions[old.sessionID] != replacement {
		t.Fatal("stale signaling changed the replacement")
	}
	manager.CloseAll()
}
