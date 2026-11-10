package sysconfig

import "testing"

// A Windows agent started without a Docker endpoint probed and logged
// /var/run/docker.sock, a path that cannot exist there. Windows must default
// to Docker's named pipe, every other OS keeps the Unix socket, and each
// default must pass the docker_endpoint check that LoadConfig applies.
func TestDefaultDockerEndpointPerOS(t *testing.T) {
	for goos, want := range map[string]string{
		"windows": "npipe:////./pipe/docker_engine",
		"linux":   "/var/run/docker.sock",
		"darwin":  "/var/run/docker.sock",
		"freebsd": "/var/run/docker.sock",
	} {
		got := defaultDockerEndpointForOS(goos)
		if got != want {
			t.Errorf("default Docker endpoint on %s = %q, want %q", goos, got, want)
		}
		normalized, err := NormalizeAgentSettingValue(SettingKeyDockerEndpoint, got)
		if err != nil || normalized != got {
			t.Errorf("default Docker endpoint on %s normalizes to %q, %v; want it unchanged", goos, normalized, err)
		}
	}
}
