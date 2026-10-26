package agentcore

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

type gatedTelemetrySender struct {
	telemetrySender
	calls   int
	blocked chan struct{}
	release chan struct{}
}

func (s *gatedTelemetrySender) Send(msg protocol.Message) error {
	s.calls++
	if s.calls == 2 {
		close(s.blocked)
		<-s.release
	}
	return s.telemetrySender.Send(msg)
}

// The actual socket sends the first sample, then disconnects while the second
// send is held. Live publishes must not block or overtake the retained tail;
// overflow must retain the newest 60 rather than restoring an old batch over it.
func TestTelemetryReplayRetainsTailDuringConcurrentPublish(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		name := "retained-tail"
		if overflow {
			name = "newest-sixty"
		}
		t.Run(name, func(t *testing.T) {
			transport, messages, cleanup := newAgentcoreCapturedTransport(t)
			defer cleanup()
			transport.connected = true
			queue := NewRingBuffer[TelemetrySample](60)
			for i := 1; i <= 3; i++ {
				queue.Push(TelemetrySample{CPUPercent: float64(i)})
			}
			sender := &gatedTelemetrySender{
				telemetrySender: transport.senderForConnection(transport.conn),
				blocked:         make(chan struct{}), release: make(chan struct{}),
			}
			done := make(chan error, 1)
			go func() {
				done <- flushTelemetrySamples(queue, func(sample TelemetrySample) error { return sendTelemetrySample(sender, sample) })
			}()
			released := false
			finished := false
			defer func() {
				if !released {
					close(sender.release)
				}
				if !finished {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("replay worker did not stop")
					}
				}
			}()
			select {
			case <-sender.blocked:
			case <-time.After(2 * time.Second):
				t.Fatal("second send not reached")
			}
			requireTelemetryCPU(t, messages, 1)
			runtime := NewRuntime(RuntimeConfig{AssetID: "node-1"}, nil, &recordingHeartbeatPublisher{})
			runtime.transport, runtime.telemetryBuf = transport, queue
			last := 4
			if overflow {
				last = 64
			}
			published := make(chan struct{})
			go func() {
				defer close(published)
				for i := 4; i <= last; i++ {
					runtime.sample = TelemetrySample{CPUPercent: float64(i)}
					runtime.publishOnce(context.Background())
				}
			}()
			defer func() {
				if !released {
					close(sender.release)
					released = true
				}
				select {
				case <-published:
				case <-time.After(2 * time.Second):
					t.Error("publisher did not stop")
				}
			}()
			select {
			case <-published:
			case <-time.After(2 * time.Second):
				t.Fatal("live publisher blocked behind replay")
			}
			transport.Close()
			close(sender.release)
			released = true
			select {
			case err := <-done:
				finished = true
				if !errors.Is(err, errNotConnected) {
					t.Fatalf("failed replay error = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("failed send did not end replay")
			}
			first := 2
			if overflow {
				first = 5
			}
			if queue.Len() != last-first+1 {
				t.Fatalf("retained count = %d", queue.Len())
			}
			replacement, resumed, stopReplacement := newAgentcoreCapturedTransport(t)
			defer stopReplacement()
			replacement.connected = true
			if err := replayBufferedTelemetry(replacement, queue); err != nil {
				t.Fatal(err)
			}
			for i := first; i <= last; i++ {
				requireTelemetryCPU(t, resumed, float64(i))
			}
			if queue.Len() != 0 {
				t.Fatalf("successful replay left %d samples", queue.Len())
			}
		})
	}
}

func TestRuntimePublishOnceRetainsFailedConnectedSend(t *testing.T) {
	transport, _, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	transport.connected = true
	// Keep the connection state true while the underlying socket is already
	// closed, reproducing the previous Connected-to-Send loss without timing.
	if err := transport.conn.Close(); err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(RuntimeConfig{}, nil, &recordingHeartbeatPublisher{})
	runtime.transport = transport
	runtime.telemetryBuf = NewRingBuffer[TelemetrySample](60)
	runtime.sample = TelemetrySample{CPUPercent: 37}
	runtime.publishOnce(context.Background())
	retained := runtime.telemetryBuf.Drain()
	if len(retained) != 1 || retained[0].CPUPercent != 37 {
		t.Fatalf("failed send lost sample: %+v", retained)
	}
}

// A successful send can finish after producers overwrite its exact circular
// slot. Its completion must never acknowledge the replacement sample.
func TestRingBufferFlushPreservesOverflowReplacement(t *testing.T) {
	queue := NewRingBuffer[int](3)
	queue.Push(1)
	var sent []int
	if err := queue.Flush(func(value int) error {
		sent = append(sent, value)
		if value == 1 {
			for i := 2; i <= 5; i++ {
				queue.Push(i)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sent, []int{1, 3, 4}) {
		t.Fatalf("sent %v; overwritten head retired its replacement", sent)
	}
	if retained := queue.Drain(); !reflect.DeepEqual(retained, []int{5}) {
		t.Fatalf("retained %v", retained)
	}
	for _, value := range queue.data {
		if value != 0 {
			t.Fatal("consumed backing slot retained its value")
		}
	}
}

func requireTelemetryCPU(t *testing.T, messages <-chan protocol.Message, cpu float64) {
	t.Helper()
	message := waitForCapturedAgentMessage(t, messages, protocol.MsgTelemetry, 2*time.Second)
	var sample protocol.TelemetryData
	if err := json.Unmarshal(message.Data, &sample); err != nil {
		t.Fatal(err)
	}
	if sample.CPUPercent != cpu {
		t.Fatalf("telemetry CPU = %v, want %v", sample.CPUPercent, cpu)
	}
}

func TestTelemetryReplayDiscardsInvalidHeadAndSendsValidTail(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()
	transport.connected = true
	queue := NewRingBuffer[TelemetrySample](60)
	invalidTemperature := math.Inf(1)
	queue.Push(TelemetrySample{CPUPercent: math.NaN()})
	queue.Push(TelemetrySample{TempCelsius: &invalidTemperature})
	queue.Push(TelemetrySample{NetRXBytesPerSec: math.Inf(-1)})
	queue.Push(TelemetrySample{CPUPercent: 21})
	if err := replayBufferedTelemetry(transport, queue); err != nil {
		t.Fatal(err)
	}
	requireTelemetryCPU(t, messages, 21)
	if queue.Len() != 0 {
		t.Fatalf("invalid head blocked %d samples", queue.Len())
	}
}
