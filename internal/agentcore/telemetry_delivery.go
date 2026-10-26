package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/labtether/protocol"
)

type telemetrySender interface {
	agentMessageSender
	AssetID() string
}

// Capture one socket for the whole flush. Reconnect must not carry an old
// replay worker onto a new connection. Each socket write already has a 10s
// deadline, and Flush attempts at most the queue's capacity (60) per call.
func replayBufferedTelemetry(transport *wsTransport, telemetryBuf *RingBuffer[TelemetrySample]) error {
	if transport == nil || telemetryBuf == nil {
		return nil
	}
	var sender *sessionMessageSender
	return flushTelemetrySamples(telemetryBuf, func(sample TelemetrySample) error {
		// Claim the flush before consulting transport state: a competing producer
		// must not wait behind the active sender's socket write lock.
		if sender == nil {
			transport.mu.Lock()
			conn := transport.conn
			transport.mu.Unlock()
			sender = transport.senderForConnection(conn)
			if sender == nil {
				return errNotConnected
			}
		}
		return sendTelemetrySample(sender, sample)
	})
}

func flushTelemetrySamples(telemetryBuf *RingBuffer[TelemetrySample], send func(TelemetrySample) error) error {
	invalid := 0
	var firstInvalid error
	err := telemetryBuf.Flush(func(sample TelemetrySample) error {
		err := send(sample)
		if errors.Is(err, errDiscardBufferedItem) {
			invalid++
			if firstInvalid == nil {
				firstInvalid = err
			}
		}
		return err
	})
	// At most one diagnostic per bounded flush, never the sample payload.
	if invalid > 0 {
		log.Printf("agentws: discarded %d invalid telemetry samples: %v", invalid, firstInvalid)
	}
	return err
}

func sendTelemetrySample(sender telemetrySender, sample TelemetrySample) error {
	assetID := sender.AssetID()
	if assetID == "" {
		assetID = sample.AssetID
	}
	td := protocol.TelemetryData{
		AssetID:          assetID,
		CPUPercent:       sample.CPUPercent,
		MemoryPercent:    sample.MemoryPercent,
		DiskPercent:      sample.DiskPercent,
		NetRXBytesPerSec: sample.NetRXBytesPerSec,
		NetTXBytesPerSec: sample.NetTXBytesPerSec,
		TempCelsius:      sample.TempCelsius,
	}
	data, err := json.Marshal(td)
	if err != nil {
		return fmt.Errorf("%w: %v", errDiscardBufferedItem, err)
	}
	return sender.Send(protocol.Message{Type: protocol.MsgTelemetry, Data: data})
}
