package streaminput

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWriterKeepsStreamBytesOrderedWhenBackendStalls(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	writer := New(local, nil)
	defer writer.Close()

	// No reader exists yet: each enqueue must return while the first write is
	// blocked. A later newline must never overtake the command before it.
	for _, text := range []string{"echo ", "safe", "\n"} {
		if err := writer.Enqueue([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len("echo safe\n"))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "echo safe\n" {
		t.Fatalf("stream reordered: %q", got)
	}
}

func TestWriterOverflowClosesStalledSessionWithoutBlockingCaller(t *testing.T) {
	for _, byBytes := range []bool{false, true} {
		t.Run(map[bool]string{false: "message limit", true: "byte limit"}[byBytes], func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			writer := New(local, nil)
			defer writer.Close()
			result := make(chan error, 1)
			go func() {
				data := []byte("x")
				if byBytes {
					data = make([]byte, MaxQueuedBytes+1)
				}
				for i := 0; i <= MaxQueuedMessages+1; i++ {
					if err := writer.Enqueue(data); err != nil {
						result <- err
						return
					}
				}
				result <- nil
			}()
			select {
			case err := <-result:
				if !errors.Is(err, ErrBacklog) {
					t.Fatalf("overflow error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("stalled input blocked the socket reader")
			}
			if writer.Reason("") != ErrBacklog.Error() {
				t.Fatalf("close reason=%q", writer.Reason(""))
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("stalled session remained open: %v", err)
			}
			if err := writer.Enqueue([]byte("later")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("closed session accepted input: %v", err)
			}
		})
	}
}

func TestWriterCloseDiscardsQueuedInputAndUnblocksWrite(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	writer := New(local, nil)
	for _, text := range []string{"old command", "\n"} {
		if err := writer.Enqueue([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("queued input survived close: %v", err)
	}
	if err := writer.Enqueue([]byte("replacement input")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("old writer accepted replacement input: %v", err)
	}
}
