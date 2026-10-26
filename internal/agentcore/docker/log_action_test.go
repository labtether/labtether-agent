package docker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestHandleDockerActionContainerLogsRejectsIncompleteOutput(t *testing.T) {
	truncated := append(dockerMuxFrame(1, "complete first line\n"), dockerMuxFrame(2, "cut off")[:10]...)
	tooLarge := bytes.Repeat(dockerMuxFrame(1, strings.Repeat("x", 60*1024)+"\n"), 35)
	// Raw TTY text may resemble a binary frame; inspect decides the encoding.
	ttyText := string(dockerMuxFrame(1, "raw terminal text"))
	for _, tc := range []struct {
		name      string
		tty       bool
		body      []byte
		want      string
		wantError string
	}{
		{name: "truncated frame after valid output", body: truncated, wantError: "truncated Docker log payload"},
		{name: "bounded complete response", body: tooLarge, wantError: "exceeds 2 MiB"},
		{name: "raw TTY content", tty: true, body: []byte(ttyText), want: ttyText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := newRecordingCollectorTransport(true)
			srv, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/containers/abc123/json":
					_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]bool{"Tty": tc.tty}})
				case "/containers/abc123/logs":
					_, _ = w.Write(tc.body)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			dc := NewDockerCollector("/tmp/docker.sock", transport, "asset-1", 30*time.Second)
			dc.client = client
			raw, err := json.Marshal(protocol.DockerActionData{
				RequestID: "bounded-logs", Action: "container.logs", ContainerID: "abc123",
			})
			if err != nil {
				t.Fatal(err)
			}
			dc.HandleDockerAction(transport, protocol.Message{Type: protocol.MsgDockerAction, Data: raw})
			msg := waitForCollectorMessage(t, transport, time.Second)
			if msg.Type != protocol.MsgDockerActionResult {
				t.Fatalf("message type = %q", msg.Type)
			}
			var result protocol.DockerActionResultData
			if err := json.Unmarshal(msg.Data, &result); err != nil {
				t.Fatal(err)
			}
			if tc.wantError != "" {
				if result.Success || !strings.Contains(result.Error, tc.wantError) || result.Data != "" {
					t.Fatalf("result success=%t, error=%q, data bytes=%d", result.Success, result.Error, len(result.Data))
				}
			} else if !result.Success || result.Data != tc.want {
				t.Fatalf("result success=%t, error=%q, data=%q; want=%q", result.Success, result.Error, result.Data, tc.want)
			}
		})
	}
}
