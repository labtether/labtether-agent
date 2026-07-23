//go:build !windows

package docker

import (
	"errors"
	"net/http"
)

var errDockerNpipeUnsupported = errors.New("Docker npipe endpoints are supported only on Windows")

func newDockerNpipeTransport(string) (*http.Transport, error) {
	return nil, errDockerNpipeUnsupported
}
