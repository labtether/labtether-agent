package netid

import (
	"net"
	"testing"
)

// Captured shape of `networksetup -listallhardwareports` on macOS 27, with
// documentation-range addresses.
const hardwarePortsSample = `
Hardware Port: Ethernet
Device: en0
Ethernet Address: 00:00:5e:00:53:01

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 00:00:5e:00:53:02

Hardware Port: Wi-Fi
Device: en1
Ethernet Address: 00:00:5e:00:53:03

Hardware Port: Thunderbolt 1
Device: en2
Ethernet Address: N/A

VLAN Configurations
===================
`

// macOS 27 gives the agent 02:00:00:00:00:00 for every interface, so the
// heartbeat's mac_address and the interface list showed no real address. The
// resolver must swap a placeholder for the hardware port's address, keep a
// real address as it is, and give none when the system has no address.
func TestMACResolverReplacesPlaceholdersWithHardwarePortAddresses(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	loads := 0
	r := &MACResolver{load: func() map[string]net.HardwareAddr {
		loads++
		return parseHardwarePorts(hardwarePortsSample)
	}}
	if got := r.Resolve("en9", mac("00:00:5e:00:53:99")); got.String() != "00:00:5e:00:53:99" || loads != 0 {
		t.Fatalf("real address: got %q after %d loads, want it unchanged and no networksetup call", got, loads)
	}
	if got := r.Resolve("en0", mac("02:00:00:00:00:00")); got.String() != "00:00:5e:00:53:01" {
		t.Fatalf("en0: got %q, want the hardware port address", got)
	}
	if got := r.Resolve("en2", mac("02:00:00:00:00:00")); got != nil {
		t.Fatalf("port without an address: got %q, want none", got)
	}
	if got := r.Resolve("awdl0", mac("02:00:00:00:00:00")); got != nil {
		t.Fatalf("interface that is not a hardware port: got %q, want none", got)
	}
	if got := r.Resolve("utun0", nil); got != nil {
		t.Fatalf("interface without a link address: got %q, want none", got)
	}
	if loads != 1 {
		t.Fatalf("networksetup asked %d times, want once per pass", loads)
	}
}

// Linux and Windows have no second source. A real all-zero address there (a
// bond with no members) must still be listed as the kernel reports it.
func TestMACResolverWithoutSecondSourceKeepsAddresses(t *testing.T) {
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	if got := (&MACResolver{}).Resolve("bond0", zero); got.String() != zero.String() {
		t.Fatalf("got %q, want the kernel's address unchanged", got)
	}
}
