package netid

import (
	"net"
	"testing"
)

// The host IP in discovered service URLs was the first IPv4 address in
// interface order, which on a Windows VM was its Tailscale address (100.x)
// although it has a LAN address. Other LAN machines cannot open that URL.
func TestChooseHostIPPrefersTheLANAddress(t *testing.T) {
	c := func(iface, ip string) hostIPCandidate { return hostIPCandidate{iface: iface, ip: net.ParseIP(ip)} }
	tailnetFirst := []hostIPCandidate{
		c("Tailscale", "100.101.102.103"), c("docker0", "172.17.0.1"),
		c("Ethernet", "fe80::1"), c("Ethernet", "192.0.2.10"), c("Ethernet", "169.254.3.4"),
	}
	if got := chooseHostIP(tailnetFirst, nil); got != "192.0.2.10" {
		// 192.0.2.10 is a documentation address, ranked as a non-private LAN address.
		t.Fatalf("got %s, want the Ethernet address", got)
	}
	private := []hostIPCandidate{c("tailscale0", "100.64.0.9"), c("br-1a2b", "172.18.0.1"), c("ens18", "10.0.0.5")}
	if got := chooseHostIP(private, nil); got != "10.0.0.5" {
		t.Fatalf("got %s, want 10.0.0.5", got)
	}
	if got := chooseHostIP(private, net.ParseIP("10.0.0.5")); got != "10.0.0.5" {
		t.Fatalf("route address: got %s", got)
	}
	if got := chooseHostIP([]hostIPCandidate{c("tailscale0", "100.64.0.9")}, nil); got != "100.64.0.9" {
		t.Fatalf("only a tailnet address: got %s", got)
	}
}
