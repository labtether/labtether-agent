package sysconfig

import (
	"fmt"
	"net"
	"strings"
)

// WindowsNetworkSnapshot holds the pre-apply state captured for rollback.
type WindowsNetworkSnapshot struct {
	// InterfaceName is the netsh interface name (e.g. "Ethernet", "Wi-Fi").
	InterfaceName string
	// WasDHCP is true when the interface was configured via DHCP before apply.
	WasDHCP bool
	// DHCPModeKnown is true only when the snapshot parser positively identified
	// whether the address mode was DHCP or static.
	DHCPModeKnown bool
	// StaticIP is the static IP address that was configured before apply, if
	// any. Empty when WasDHCP is true.
	StaticIP string
	// SubnetMask is the subnet mask associated with StaticIP.
	SubnetMask string
	// Gateway is the default gateway that was configured before apply, if any.
	Gateway string
	// DNSServers are the DNS servers that were configured before apply.
	DNSServers []string
	// DNSWasDHCP and DNSModeKnown preserve the DNS source independently of the
	// currently assigned server list. DHCP-assigned servers must not be restored
	// as a static configuration.
	DNSWasDHCP   bool
	DNSModeKnown bool
}

// CaptureWindowsNetworkSnapshot reads the current IP and DNS configuration
// for the given interface using netsh.
func CaptureWindowsNetworkSnapshot(iface string) (*WindowsNetworkSnapshot, error) {
	snapshot := &WindowsNetworkSnapshot{InterfaceName: iface}

	// Query IP config.
	ipOut, ipErr := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
		"netsh", "interface", "ip", "show", "config", iface)
	if ipErr != nil {
		trimmed := TruncateCommandOutput(ipOut, MaxCommandOutputBytes)
		if trimmed == "" {
			return nil, fmt.Errorf("netsh show config for %s: %w", iface, ipErr)
		}
		return nil, fmt.Errorf("netsh show config for %s: %s", iface, trimmed)
	}
	ParseWindowsIPConfig(string(ipOut), snapshot)
	if !snapshot.DHCPModeKnown {
		return nil, fmt.Errorf("netsh show config for %s returned an unrecognized or localized DHCP mode", iface)
	}
	if !snapshot.WasDHCP {
		if net.ParseIP(snapshot.StaticIP).To4() == nil {
			return nil, fmt.Errorf("netsh show config for %s did not return a valid static IPv4 address", iface)
		}
		maskIP := net.ParseIP(snapshot.SubnetMask).To4()
		_, maskBits := net.IPMask(maskIP).Size()
		if maskIP == nil || maskBits != 32 {
			return nil, fmt.Errorf("netsh show config for %s did not return a valid subnet mask", iface)
		}
		if snapshot.Gateway != "" && net.ParseIP(snapshot.Gateway).To4() == nil {
			return nil, fmt.Errorf("netsh show config for %s returned an invalid gateway", iface)
		}
	}

	// Query DNS config.
	dnsOut, dnsErr := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
		"netsh", "interface", "ip", "show", "dnsservers", iface)
	if dnsErr != nil {
		trimmed := TruncateCommandOutput(dnsOut, MaxCommandOutputBytes)
		if trimmed == "" {
			return nil, fmt.Errorf("netsh show dnsservers for %s: %w", iface, dnsErr)
		}
		return nil, fmt.Errorf("netsh show dnsservers for %s: %s", iface, trimmed)
	}
	ParseWindowsDNSConfig(string(dnsOut), snapshot)
	if !snapshot.DNSModeKnown {
		return nil, fmt.Errorf("netsh show dnsservers for %s returned an unrecognized or localized DNS mode", iface)
	}
	for _, server := range snapshot.DNSServers {
		if net.ParseIP(server) == nil {
			return nil, fmt.Errorf("netsh show dnsservers for %s returned an invalid DNS server", iface)
		}
	}

	return snapshot, nil
}

// ParseWindowsIPConfig parses the output of
// "netsh interface ip show config <iface>" and populates snapshot.
func ParseWindowsIPConfig(raw string, snapshot *WindowsNetworkSnapshot) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.Contains(lower, "dhcp enabled") {
			value := strings.ToLower(extractNetshValue(line))
			snapshot.DHCPModeKnown = value == "yes" || value == "no"
			snapshot.WasDHCP = value == "yes"
			continue
		}
		if strings.HasPrefix(lower, "ip address:") {
			snapshot.StaticIP = extractNetshValue(line)
			continue
		}
		if strings.HasPrefix(lower, "subnet prefix:") || strings.HasPrefix(lower, "subnet mask:") {
			snapshot.SubnetMask = normalizeNetshSubnetMask(extractNetshValue(line))
			continue
		}
		if strings.HasPrefix(lower, "default gateway:") {
			snapshot.Gateway = extractNetshValue(line)
			continue
		}
	}
}

// ParseWindowsDNSServers parses the output of
// "netsh interface ip show dnsservers <iface>" and returns the list of servers.
func ParseWindowsDNSServers(raw string) []string {
	snapshot := &WindowsNetworkSnapshot{}
	ParseWindowsDNSConfig(raw, snapshot)
	return snapshot.DNSServers
}

// ParseWindowsDNSConfig parses DNS server addresses and, critically, whether
// they came from DHCP or a static configuration. Unknown/localized labels leave
// DNSModeKnown false so callers can fail closed before changing the interface.
func ParseWindowsDNSConfig(raw string, snapshot *WindowsNetworkSnapshot) {
	var dhcpServers, staticServers []string
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		// Lines carrying a server address start with "DNS servers configured through" or
		// have an IP on the right side of a colon-delimited label.
		if strings.HasPrefix(lower, "dns servers configured through dhcp:") {
			section = "dhcp"
			val := extractNetshValue(line)
			if val != "" && !strings.EqualFold(val, "none") {
				dhcpServers = append(dhcpServers, val)
			}
			continue
		}
		if strings.HasPrefix(lower, "statically configured dns servers:") {
			section = "static"
			val := extractNetshValue(line)
			if val != "" && !strings.EqualFold(val, "none") {
				staticServers = append(staticServers, val)
			}
			continue
		}
		// Additional servers appear as lines with only an IP (no label).
		if isIPAddress(line) {
			switch section {
			case "dhcp":
				dhcpServers = append(dhcpServers, line)
			case "static":
				staticServers = append(staticServers, line)
			}
		}
	}
	if len(staticServers) > 0 {
		snapshot.DNSModeKnown = true
		snapshot.DNSWasDHCP = false
		snapshot.DNSServers = staticServers
		return
	}
	if len(dhcpServers) > 0 {
		snapshot.DNSModeKnown = true
		snapshot.DNSWasDHCP = true
		snapshot.DNSServers = dhcpServers
		return
	}
	// Both sections saying "None" is insufficient to distinguish static from
	// DHCP. Leaving the mode unknown is safer than inventing rollback state.
	snapshot.DNSServers = nil
}

// CloneWindowsNetworkSnapshot returns a deep copy of snapshot.
func CloneWindowsNetworkSnapshot(snapshot *WindowsNetworkSnapshot) *WindowsNetworkSnapshot {
	if snapshot == nil {
		return nil
	}
	clone := *snapshot
	clone.DNSServers = CloneStringSlice(snapshot.DNSServers)
	return &clone
}

// extractNetshValue extracts the value portion of a "Label: value" line.
func extractNetshValue(line string) string {
	if idx := strings.Index(line, ":"); idx >= 0 {
		return strings.TrimSpace(line[idx+1:])
	}
	return strings.TrimSpace(line)
}

// isIPAddress returns true when s looks like an IPv4 or IPv6 address.
// It uses a simple heuristic: the part before any zone-ID separator (%) must
// contain only hex digits, dots, and colons; the zone ID (after %) may contain
// any word characters.
func isIPAddress(s string) bool {
	if s == "" {
		return false
	}
	// Strip optional IPv6 zone ID (e.g. "fe80::1%eth0" → "fe80::1").
	addr := s
	if idx := strings.Index(s, "%"); idx >= 0 {
		addr = s[:idx]
	}
	if addr == "" {
		return false
	}
	for _, ch := range addr {
		if !((ch >= '0' && ch <= '9') ||
			(ch >= 'a' && ch <= 'f') ||
			(ch >= 'A' && ch <= 'F') ||
			ch == '.' || ch == ':') {
			return false
		}
	}
	// Must contain at least one dot or colon to distinguish from plain numbers.
	return strings.ContainsAny(addr, ".:")
}
