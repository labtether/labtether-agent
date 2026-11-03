package netid

import (
	"net"
	"strings"
)

// PrimaryIP returns the address other LAN machines reach this host on: the
// default route's address when it is a LAN address, else the best ranked
// one. "" when the host has none. The Hub shows it as the device's address
// and service URLs use it.
func PrimaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	candidates := make([]hostIPCandidate, 0, 8)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			if ip := ipFromAddr(addr); ip != nil {
				candidates = append(candidates, hostIPCandidate{iface: iface.Name, ip: ip})
			}
		}
	}
	return chooseHostIP(candidates, DefaultRouteIP())
}

type hostIPCandidate struct {
	iface string
	ip    net.IP
}

var virtualInterfacePrefixes = []string{"docker", "br-", "veth", "virbr", "vnet", "tailscale", "tun", "tap", "wg", "zt", "utun", "lxc", "cni", "flannel", "cali", "kube"}

// hostIPRank orders addresses for the service URLs this host advertises:
// a LAN address first. Before, the first IPv4 address in interface order
// won, which on many hosts is a Tailscale (100.64.0.0/10) or Docker bridge
// address that other LAN machines cannot reach. -1 means never.
func hostIPRank(c hostIPCandidate) int {
	ip := c.ip
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return -1
	}
	name := strings.ToLower(c.iface)
	virtual := false
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			virtual = true
			break
		}
	}
	v4 := ip.To4()
	if v4 == nil {
		return 5
	}
	cgnat := v4[0] == 100 && v4[1]&0xC0 == 64
	switch {
	case cgnat:
		return 4
	case !virtual && v4.IsPrivate():
		return 0
	case !virtual:
		return 1
	case v4.IsPrivate():
		return 2
	}
	return 3
}

// chooseHostIP prefers the address the default route uses when it is a LAN
// address, then the best ranked one (interface order breaks ties).
func chooseHostIP(candidates []hostIPCandidate, routeIP net.IP) string {
	best, bestRank := "", 99
	for _, c := range candidates {
		rank := hostIPRank(c)
		if rank < 0 {
			continue
		}
		if routeIP != nil && c.ip.Equal(routeIP) && rank <= 1 {
			return c.ip.String()
		}
		if rank < bestRank {
			best, bestRank = c.ip.String(), rank
		}
	}
	return best
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}
