package backends

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func wevtutilEventXML(recordID int, second int, message string) string {
	return fmt.Sprintf("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"+
		"<Provider Name='ltqa'/><EventRecordID>%d</EventRecordID><Level>4</Level>"+
		"<TimeCreated SystemTime='2026-11-11T00:00:%02d.5000000Z'/></System>"+
		"<RenderingInfo Culture='en-US'><Message>%s</Message></RenderingInfo></Event>\n", recordID, second, message)
}

// The stream asked for events at or after the newest event's time, cut to whole
// seconds, so the newest events were sent again on every poll: on a lab
// Windows VM 11 events reached the Hub 257 times in 30 minutes.
func TestWindowsLogStreamSendsEachEventOnce(t *testing.T) {
	original, originalPoll := RunWevtutilCommand, wevtutilStreamPollInterval
	t.Cleanup(func() { RunWevtutilCommand, wevtutilStreamPollInterval = original, originalPoll })
	wevtutilStreamPollInterval = 5 * time.Millisecond

	// The channel holds events 7 and 8 when the stream starts; 9 and 10 arrive later, in the same second as 8.
	var mu sync.Mutex
	available := []string{wevtutilEventXML(7, 1, "old seven"), wevtutilEventXML(8, 2, "old eight")}
	polls := 0
	RunWevtutilCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "/rd:true") && strings.Contains(joined, "/c:1") {
			return utf16LE(available[len(available)-1]), nil
		}
		polls++
		if polls == 2 {
			available = append(available, wevtutilEventXML(9, 2, "new nine"), wevtutilEventXML(10, 2, "new ten"))
		}
		var after int
		if _, err := fmt.Sscanf(joined[strings.Index(joined, "EventRecordID>")+len("EventRecordID>"):], "%d", &after); err != nil {
			t.Errorf("stream query without a record number: %q", joined)
		}
		var out strings.Builder
		for i := after - 6; i < len(available); i++ { // record N is available[N-7]
			if i >= 0 {
				out.WriteString(available[i])
			}
		}
		return utf16LE(out.String()), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = (WindowsLogBackend{Channels: "System"}).StreamEntries(ctx, func(entry protocol.LogStreamData) {
			mu.Lock()
			got = append(got, entry.Message)
			mu.Unlock()
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		enough := polls >= 6
		mu.Unlock()
		if enough || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != "new nine,new ten" {
		t.Fatalf("streamed %q, want each new event once: new nine,new ten", got)
	}
}
