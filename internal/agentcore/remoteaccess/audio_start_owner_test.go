package remoteaccess

import (
	"context"
	"encoding/json"
	"github.com/labtether/protocol"
	"io"
	"sync"
	"testing"
	"time"
)

type audioOwnedReader struct {
	closed chan struct{}
	once   sync.Once
}

func (r *audioOwnedReader) Read([]byte) (int, error) { return 0, io.EOF }
func (r *audioOwnedReader) Close() error             { r.once.Do(func() { close(r.closed) }); return nil }
func TestAudioPreparedStopCancelsLateCaptureAndPreservesReplacement(t *testing.T) {
	original := StartAudioCapture
	defer func() { StartAudioCapture = original }()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	reader := &audioOwnedReader{closed: make(chan struct{})}
	var captureCtx context.Context
	StartAudioCapture = func(ctx context.Context, _ string, _ int) (io.Reader, error) {
		captureCtx = ctx
		close(entered)
		<-release
		return reader, nil
	}
	manager := NewAudioSidebandManager()
	defer manager.CloseAll()
	sender := &terminalStartMessages{}
	raw, _ := json.Marshal(protocol.DesktopAudioStartData{SessionID: "same"})
	msg := protocol.Message{Data: raw}
	start := manager.PrepareAudioStart(sender, msg)
	if start == nil {
		t.Fatal("missing audio reservation")
	}
	start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("capture did not begin")
	}
	stopRaw, _ := json.Marshal(protocol.DesktopAudioStopData{SessionID: "same"})
	stop := manager.PrepareAudioStop(sender, protocol.Message{Data: stopRaw})
	if stop == nil {
		t.Fatal("stop did not claim owner")
	}
	if captureCtx.Err() == nil {
		t.Fatal("stop did not cancel inline")
	}
	if manager.PrepareAudioStop(sender, protocol.Message{Data: stopRaw}) != nil {
		t.Fatal("duplicate stop claimed owner")
	}
	if manager.PrepareAudioStart(sender, msg) == nil {
		t.Fatal("new capture reservation rejected")
	}
	manager.Mu.Lock()
	replacement := manager.Sessions["same"]
	manager.Mu.Unlock()
	unblock()
	select {
	case <-reader.closed:
	case <-time.After(time.Second):
		t.Fatal("canceled late capture reader leaked")
	}
	manager.Mu.Lock()
	kept := manager.Sessions["same"] == replacement
	manager.Mu.Unlock()
	if !kept {
		t.Fatal("old capture removed replacement")
	}
	if len(sender.snapshot()) != 0 {
		t.Fatal("old capture sent state after stop")
	}
	stop()
}
