package netid

import (
	"net"
	"testing"
)

// Wake-on-LAN for an agent device had no MAC to send to. The address must be
// the one on the default route, not a Docker bridge or a VPN interface.
func TestChoosePrimaryMACPrefersTheDefaultRouteInterface(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	nics := []nic{
		{name: "lo", up: true, loopback: true, ips: []net.IP{net.ParseIP("127.0.0.1")}},
		{name: "docker0", mac: mac("02:42:ac:11:00:01"), up: true, ips: []net.IP{net.ParseIP("172.17.0.1")}},
		{name: "enp3s0", mac: mac("aa:bb:cc:00:00:01"), up: true, ips: []net.IP{net.ParseIP("192.0.2.10")}},
		{name: "eno1", mac: mac("aa:bb:cc:00:00:02"), up: false},
	}
	if got := choosePrimaryMAC(nics, net.ParseIP("192.0.2.10")); got != "aa:bb:cc:00:00:01" {
		t.Fatalf("default route: got %q", got)
	}
	if got := choosePrimaryMAC(nics, nil); got != "aa:bb:cc:00:00:01" {
		t.Fatalf("no route: got %q, want the wired interface, not docker0", got)
	}
	if got := choosePrimaryMAC(nics[:2], nil); got != "" {
		t.Fatalf("only virtual: got %q, want none", got)
	}
}
