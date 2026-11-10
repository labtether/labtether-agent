package sysconfig

import "runtime"

// DefaultDockerEndpoint is the local Docker Engine endpoint the agent uses
// when none is configured: Docker's named pipe on Windows and its Unix
// socket everywhere else.
func DefaultDockerEndpoint() string {
	return defaultDockerEndpointForOS(runtime.GOOS)
}

func defaultDockerEndpointForOS(goos string) string {
	if goos == "windows" {
		return "npipe:////./pipe/docker_engine"
	}
	return "/var/run/docker.sock"
}
