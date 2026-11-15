package netid

import (
	"bufio"
	"net"
	"strings"
)

// redactedMAC is what macOS 27 puts in the interface list (sysctl
// NET_RT_IFLIST, getifaddrs, ifconfig) in place of every interface's address
// for a process started under a non-Apple program, such as the agent under
// the LabTether menu bar app.
var redactedMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}

// IsPlaceholderMAC reports whether mac is a stand-in rather than a real
// hardware address: the macOS redaction value or all zeros. Wake-on-LAN to
// such an address reaches no machine.
func IsPlaceholderMAC(mac net.HardwareAddr) bool {
	if len(mac) == 0 {
		return false
	}
	if mac.String() == redactedMAC.String() {
		return true
	}
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// MACResolver gives an interface's real hardware address when the interface
// list returned a placeholder. It asks the system (on macOS through
// networksetup) at most once, and only after it sees a placeholder.
type MACResolver struct {
	load   func() map[string]net.HardwareAddr
	loaded bool
	byName map[string]net.HardwareAddr
}

// NewMACResolver returns a resolver for one pass over the interface list.
func NewMACResolver() *MACResolver {
	return &MACResolver{load: hardwareMACs}
}

// Resolve returns mac when it is real, the system's hardware address for name
// when mac is a placeholder, and nil when no real address is known. Where
// there is no second source (Linux, Windows) it returns mac unchanged, so
// their interface lists stay as the kernel reports them.
func (r *MACResolver) Resolve(name string, mac net.HardwareAddr) net.HardwareAddr {
	if !IsPlaceholderMAC(mac) || r.load == nil {
		return mac
	}
	if !r.loaded {
		r.loaded = true
		r.byName = r.load()
	}
	if real, ok := r.byName[name]; ok && !IsPlaceholderMAC(real) {
		return real
	}
	return nil
}

// parseHardwarePorts reads `networksetup -listallhardwareports` output into
// device name -> Ethernet address. Ports without a valid address are left out.
func parseHardwarePorts(text string) map[string]net.HardwareAddr {
	out := map[string]net.HardwareAddr{}
	device := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "":
			device = ""
		case strings.HasPrefix(line, "Device:"):
			device = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
		case strings.HasPrefix(line, "Ethernet Address:") && device != "":
			mac, err := net.ParseMAC(strings.TrimSpace(strings.TrimPrefix(line, "Ethernet Address:")))
			if err == nil && len(mac) == 6 && !IsPlaceholderMAC(mac) {
				out[device] = mac
			}
		}
	}
	return out
}
