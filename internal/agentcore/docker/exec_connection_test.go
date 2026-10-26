package docker

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDockerExecCanceledConnectionUnblocksStalledReadAndWrite(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw, peer := net.Pipe()
			defer peer.Close()
			conn := bindDockerExecConnection(ctx, raw)
			defer conn.Close()
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				close(entered)
				var err error
				if operation == "read" {
					_, err = conn.Read(make([]byte, 1))
				} else {
					_, err = conn.Write([]byte("request"))
				}
				done <- err
			}()
			<-entered
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled operation succeeded after cancellation")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not close hijacked socket")
			}
		})
	}
}
