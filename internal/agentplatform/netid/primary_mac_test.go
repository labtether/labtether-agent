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

// On macOS 27 every interface reported 02:00:00:00:00:00, and the agent sent
// it as the device's MAC, so Wake-on-LAN went to an address no machine has.
// A placeholder must never be chosen; sending none is better.
func TestChoosePrimaryMACNeverReturnsAPlaceholder(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	nics := []nic{
		{name: "en0", mac: mac("02:00:00:00:00:00"), up: true, ips: []net.IP{net.ParseIP("192.0.2.10")}},
		{name: "en1", mac: mac("00:00:00:00:00:00"), up: true, ips: []net.IP{net.ParseIP("192.0.2.11")}},
	}
	if got := choosePrimaryMAC(nics, net.ParseIP("192.0.2.10")); got != "" {
		t.Fatalf("default route on a placeholder: got %q, want none", got)
	}
	if got := choosePrimaryMAC(nics, nil); got != "" {
		t.Fatalf("no route: got %q, want none", got)
	}
}
