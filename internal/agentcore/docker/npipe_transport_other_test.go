//go:build !windows

package docker

import (
	"context"
	"errors"
	"testing"
)

func TestDockerClientNpipeFailsExplicitlyOffWindows(t *testing.T) {
	err := CheckDockerEndpoint(context.Background(), "npipe:////./pipe/docker_engine")
	if !errors.Is(err, errDockerNpipeUnsupported) {
		t.Fatalf("CheckDockerEndpoint error = %v, want explicit unsupported error", err)
	}
}
