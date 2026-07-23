//go:build windows

package docker

import (
	"context"
	"net"
	"net/http"

	winio "github.com/Microsoft/go-winio"
)

func newDockerNpipeTransport(pipePath string) (*http.Transport, error) {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, pipePath)
		},
	}, nil
}
