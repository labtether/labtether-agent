// Package netid finds the network identity a Hub needs to reach a host when
// the agent cannot answer, such as the MAC address Wake-on-LAN sends to.
package netid

import (
	"net"
	"sort"
	"strings"
)

// MetadataKey is the asset metadata key the Hub reads for Wake-on-LAN.
const MetadataKey = "mac_address"

// nic is the part of a network interface PrimaryMAC looks at.
type nic struct {
	name     string
	mac      net.HardwareAddr
	up       bool
	loopback bool
	ips      []net.IP
}

// PrimaryMAC returns the MAC address of the interface that holds the source
// address of the host's default route, else of the first wired-looking
// interface that is up, else "". The Hub needs it before the host is off: a
// device that is off cannot report it, so Wake-on-LAN had nothing to send.
func PrimaryMAC() string {
	return choosePrimaryMAC(listNICs(), DefaultRouteIP())
}

func listNICs() []nic {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]nic, 0, len(ifaces))
	for _, iface := range ifaces {
		entry := nic{name: iface.Name, mac: iface.HardwareAddr,
			up: iface.Flags&net.FlagUp != 0, loopback: iface.Flags&net.FlagLoopback != 0}
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					entry.ips = append(entry.ips, ipNet.IP)
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// DefaultRouteIP asks the kernel which local address it would use to reach
// a documentation address (TEST-NET-1). A UDP dial sends no packet.
func DefaultRouteIP() net.IP {
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP
	}
	return nil
}

var virtualPrefixes = []string{"docker", "veth", "br-", "virbr", "vnet", "tailscale", "tun", "tap", "wg", "zt", "lxc", "cni", "flannel", "cali", "kube"}

func choosePrimaryMAC(nics []nic, routeIP net.IP) string {
	usable := func(n nic) bool { return n.up && !n.loopback && len(n.mac) == 6 }
	if routeIP != nil {
		for _, n := range nics {
			for _, ip := range n.ips {
				if usable(n) && ip.Equal(routeIP) {
					return n.mac.String()
				}
			}
		}
	}
	sorted := append([]nic(nil), nics...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	for _, n := range sorted {
		if !usable(n) || len(n.ips) == 0 {
			continue
		}
		virtual := false
		for _, prefix := range virtualPrefixes {
			if strings.HasPrefix(strings.ToLower(n.name), prefix) {
				virtual = true
				break
			}
		}
		if !virtual {
			return n.mac.String()
		}
	}
	return ""
}
