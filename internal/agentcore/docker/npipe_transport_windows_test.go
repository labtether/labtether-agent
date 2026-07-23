//go:build windows

package docker

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDockerClientNpipeUsesWindowsTransport(t *testing.T) {
	endpoint := "npipe:////./pipe/labtether-test-nonexistent"
	client := NewDockerClient(endpoint)
	if client.initErr != nil {
		t.Fatalf("initialize npipe client: %v", client.initErr)
	}
	if client.httpClient == nil || client.httpClient.Transport == nil || !client.localIPC {
		t.Fatal("npipe client did not configure a local Windows HTTP transport")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := client.ping(ctx)
	if err == nil {
		t.Fatal("nonexistent QA pipe unexpectedly responded")
	}
	if strings.Contains(strings.ToLower(err.Error()), "unix") {
		t.Fatalf("npipe endpoint fell through to Unix dialing: %v", err)
	}
}
