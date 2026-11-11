package backends

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/labtether/protocol"
)

// wevtutilStreamBatch is the most events read from one channel per poll; the
// rest follow on the next poll.
const wevtutilStreamBatch = 100

// StreamEntries polls each Event Log channel for events newer than the last
// one it sent (Event Log has no follow mode). Each channel numbers its events
// (EventRecordID), so the stream sends every new event once. It used to ask
// for events at or after the last event's time, cut to whole seconds, and
// sent the newest events again on every poll.
func (b WindowsLogBackend) StreamEntries(ctx context.Context, emit func(protocol.LogStreamData)) error {
	channels := b.resolvedChannels()
	last := make(map[string]uint64, len(channels))
	known := make(map[string]bool, len(channels))
	for _, ch := range channels {
		last[ch], known[ch] = b.newestRecordID(ch)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wevtutilStreamPollInterval):
		}

		for _, ch := range channels {
			if !known[ch] {
				// Start from the channel's newest event once it can be read,
				// never from the beginning of its history.
				last[ch], known[ch] = b.newestRecordID(ch)
				continue
			}
			records, err := b.recordsAfter(ch, last[ch])
			if err != nil {
				continue
			}
			for _, record := range records {
				if record.recordID <= last[ch] {
					continue
				}
				last[ch] = record.recordID
				if record.entry.Message != "" {
					emit(record.entry)
				}
			}
		}
	}
}

// newestRecordID returns the record number of the channel's newest event; an
// empty channel starts at 0.
func (b WindowsLogBackend) newestRecordID(channel string) (uint64, bool) {
	out, err := b.runWevtutil(channel, "/rd:true", "/c:1")
	if err != nil {
		return 0, false
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return 0, true
	}
	records, err := parseWevtutilRenderedXMLRecords(bytes.TrimSpace(out))
	if err != nil || len(records) == 0 {
		return 0, false
	}
	return records[0].recordID, true
}

// recordsAfter returns the channel's events after recordID, oldest first.
func (b WindowsLogBackend) recordsAfter(channel string, recordID uint64) ([]wevtutilRecord, error) {
	out, err := b.runWevtutil(channel, "/rd:false", "/c:"+strconv.Itoa(wevtutilStreamBatch),
		"/q:*[System[(EventRecordID>"+strconv.FormatUint(recordID, 10)+")]]")
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	return parseWevtutilRenderedXMLRecords(bytes.TrimSpace(out))
}

func (b WindowsLogBackend) runWevtutil(channel string, extra ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wevtutilQueryCommandTimeout)
	defer cancel()
	args := append([]string{"qe", channel, "/f:RenderedXml", wevtutilUnicodeArg}, extra...)
	out, err := RunWevtutilCommand(ctx, "wevtutil", args...)
	out = decodeWevtutilOutput(out)
	if err != nil {
		return nil, fmt.Errorf("wevtutil query failed for channel %s: %w", channel, err)
	}
	return out, nil
}
