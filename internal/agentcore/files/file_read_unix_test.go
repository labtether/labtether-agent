//go:build unix

package files

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestHandleFileReadRejectsFIFOWithoutBlockingOnOpen(t *testing.T) {
	baseDir := t.TempDir()
	fifoPath := filepath.Join(baseDir, "stream.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	fm := &Manager{BaseDir: baseDir}
	transport := &testFileTransport{}
	request := protocol.Message{Data: marshalTestMessage(t, protocol.FileReadData{
		RequestID: "fifo-read",
		Path:      "stream.fifo",
	})}

	done := make(chan struct{})
	go func() {
		fm.HandleFileRead(transport, request)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO read blocked while opening without a writer")
	}
	result := lastFileData(t, transport)
	if result.Error == "" || !strings.Contains(result.Error, "non-regular") {
		t.Fatalf("FIFO result = %+v, want non-regular-file rejection", result)
	}
	if result.Data != "" {
		t.Fatalf("FIFO rejection returned data: %q", result.Data)
	}
}

func TestHandleFileReadRejectsCharacterDevice(t *testing.T) {
	if info, err := os.Stat("/dev/zero"); err != nil || info.Mode().IsRegular() {
		t.Skip("/dev/zero character device is unavailable")
	}
	fm := &Manager{BaseDir: "/dev"}
	transport := &testFileTransport{}
	fm.HandleFileRead(transport, protocol.Message{Data: marshalTestMessage(t, protocol.FileReadData{
		RequestID: "device-read",
		Path:      "zero",
	})})

	result := lastFileData(t, transport)
	if result.Error == "" || !strings.Contains(result.Error, "non-regular") {
		t.Fatalf("device result = %+v, want non-regular-file rejection", result)
	}
	if result.Data != "" {
		t.Fatalf("device rejection returned data: %q", result.Data)
	}
}

func TestHandleFileReadRejectsUnixSocket(t *testing.T) {
	// macOS limits sockaddr_un paths to 104 bytes; t.TempDir can exceed that.
	baseDir, err := os.MkdirTemp("/tmp", "lt-file-read-socket-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(baseDir) })
	listener, err := net.Listen("unix", filepath.Join(baseDir, "agent.sock"))
	if err != nil {
		t.Fatalf("create Unix socket: %v", err)
	}
	defer listener.Close()

	fm := &Manager{BaseDir: baseDir}
	transport := &testFileTransport{}
	fm.HandleFileRead(transport, protocol.Message{Data: marshalTestMessage(t, protocol.FileReadData{
		RequestID: "socket-read",
		Path:      "agent.sock",
	})})

	result := lastFileData(t, transport)
	if result.Error == "" {
		t.Fatalf("socket result = %+v, want rejection", result)
	}
	if result.Data != "" {
		t.Fatalf("socket rejection returned data: %q", result.Data)
	}
}
