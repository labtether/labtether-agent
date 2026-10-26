package docker

import (
	"runtime"
	"testing"
)

func TestComposeDaemonEndpointBinding(t *testing.T) {
	t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	for _, test := range []struct{ endpoint, want string }{
		{"/var/run/docker.sock", "unix:///var/run/docker.sock"},
		{"unix:///run/custom.sock", "unix:///run/custom.sock"},
		{"https://localhost/engine", "tcp://localhost:443/engine"},
		{"https://127.0.0.1:8443/engine", "tcp://127.0.0.1:8443/engine"},
		{"https://[::1]/engine", "tcp://[::1]:443/engine"},
		{"http://127.0.0.1/engine", "tcp://127.0.0.1:80/engine"},
		{"http://127.0.0.1:8123/engine", "tcp://127.0.0.1:8123/engine"},
		{"http://[::1]:8123/engine", "tcp://[::1]:8123/engine"},
	} {
		got, err := composeDaemonHost(test.endpoint)
		if err != nil || got != test.want {
			t.Errorf("%q got%q err%v", test.endpoint, got, err)
		}
	}
	for _, endpoint := range []string{"http://user:pass@127.0.0.1/engine", "http://127.0.0.1/engine?q=1", "http://127.0.0.1/engine#fragment", "http://127.0.0.1/part%2Fengine", "http://127.0.0.1//engine", "http://127.0.0.1/a/../engine", "tcp://127.0.0.1:2375", "relative.sock"} {
		if _, err := composeDaemonHost(endpoint); err == nil {
			t.Errorf("accepted lossy endpoint%q", endpoint)
		}
	}
	got, err := composeDaemonHost("npipe:////./pipe/docker_engine")
	if runtime.GOOS == "windows" {
		if err != nil || got != "npipe:////./pipe/docker_engine" {
			t.Fatal(got, err)
		}
	} else if err == nil {
		t.Fatal("npipe accepted off Windows")
	}
}
