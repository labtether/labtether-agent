package docker

import (
	"context"
	"encoding/json"
	"github.com/labtether/protocol"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDockerLogManagerFramesAndVisibleErrors(t *testing.T) {
	type line struct{ stream, data string }
	mixed := append(dockerMuxFrame(2, "err a\nerr b\n"), dockerMuxFrame(1, "split ")...)
	mixed = append(mixed, dockerMuxFrame(2, "err c\n")...)
	mixed = append(mixed, dockerMuxFrame(1, "line\n")...)
	// A ten-byte payload also puts a newline byte in the binary length header.
	mixed = append(mixed, dockerMuxFrame(1, "123456789\n")...)
	mixed = append(mixed, dockerMuxFrame(2, "last")...)
	truncated := dockerMuxFrame(1, "payload")[:11]
	invalid := dockerMuxFrame(1, "hello")
	invalid[2] = 1
	rawPrefix := string(dockerMuxFrame(2, "raw terminal bytes")) + "\n"
	cases := []struct {
		name      string
		tty       bool
		wire      []byte
		want      []line
		errorText string
	}{
		{name: "multiplexed multiline and split frames", wire: mixed, want: []line{{"stderr", "err a"}, {"stderr", "err b"}, {"stderr", "err c"}, {"stdout", "split line"}, {"stdout", "123456789"}, {"stderr", "last"}}},
		{name: "TTY does not guess binary headers", tty: true, wire: []byte(rawPrefix), want: []line{{"stdout", strings.TrimSuffix(rawPrefix, "\n")}}},
		{name: "truncated header", wire: []byte{1, 0, 0}, errorText: "truncated Docker log header"},
		{name: "truncated payload", wire: truncated, errorText: "truncated Docker log payload"},
		{name: "invalid header", wire: invalid, errorText: "invalid Docker log frame header"},
		{name: "daemon error", wire: dockerMuxFrame(3, "engine reader failed"), errorText: "engine reader failed"},
		{name: "oversized multiplexed line", wire: dockerMuxFrame(1, strings.Repeat("x", maxDockerLogLineBytes+1)), errorText: "exceeds 64 KiB"},
		{name: "oversized TTY line", tty: true, wire: []byte(strings.Repeat("x", maxDockerLogLineBytes+3)), errorText: "read Docker TTY logs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/containers/ct-1/json":
					_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Tty": tc.tty}})
				case "/containers/ct-1/logs":
					if len(tc.wire) > 1024 {
						_, _ = w.Write(tc.wire)
						return
					}
					// Use the real HTTP body with headers and payload fragmented arbitrarily.
					for data := tc.wire; len(data) > 0; {
						count := min(3, len(data))
						_, _ = w.Write(data[:count])
						data = data[count:]
						w.(http.Flusher).Flush()
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			manager := NewDockerLogManager(client)
			defer manager.CloseAll()
			sender := newRecordingCollectorTransport(true)
			raw, _ := json.Marshal(protocol.DockerLogsStartData{SessionID: "logs", ContainerID: "ct-1"})
			start := manager.PrepareLogsStart(context.Background(), sender, protocol.Message{Data: raw})
			if start == nil {
				t.Fatal("log stream not prepared")
			}
			manager.mu.Lock()
			stream := manager.streams["logs"]
			manager.mu.Unlock()
			start()
			select {
			case <-stream.done:
			case <-time.After(2 * time.Second):
				t.Fatal("log stream did not finish")
			}
			sender.mu.Lock()
			messages := append([]protocol.Message(nil), sender.messages...)
			sender.mu.Unlock()
			if tc.errorText != "" {
				if len(messages) != 1 {
					t.Fatalf("error messages=%d, want one visible failure", len(messages))
				}
				var payload protocol.DockerLogsStreamData
				if err := json.Unmarshal(messages[0].Data, &payload); err != nil {
					t.Fatal(err)
				}
				if payload.Stream != "stderr" || !strings.Contains(payload.Data, "[LabTether] Docker log stream failed:") || !strings.Contains(payload.Data, tc.errorText) {
					t.Fatalf("failure not visible: %+v", payload)
				}
			} else {
				if len(messages) != len(tc.want) {
					t.Fatalf("lines=%d, want %d", len(messages), len(tc.want))
				}
				for index, msg := range messages {
					var got protocol.DockerLogsStreamData
					if err := json.Unmarshal(msg.Data, &got); err != nil {
						t.Fatal(err)
					}
					if got.SessionID != "logs" || got.Stream != tc.want[index].stream || got.Data != tc.want[index].data {
						t.Fatalf("line %d=%+v, want %+v", index, got, tc.want[index])
					}
				}
			}
			manager.mu.Lock()
			remaining := len(manager.streams)
			manager.mu.Unlock()
			if remaining != 0 {
				t.Fatal("completed log owner retained")
			}
		})
	}
}
