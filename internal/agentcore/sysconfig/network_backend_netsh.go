package sysconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labtether/protocol"
	"net"
	"strings"
)

// WindowsRunCommandWithTimeout is the command runner used by the Windows
// network backend.  It is a package-level var so tests can inject stubs.
var WindowsRunCommandWithTimeout = RunCommandWithTimeout

// WindowsNetworkBackend implements NetworkBackend using netsh and PowerShell's
// Get-NetAdapter for Windows hosts.
type WindowsNetworkBackend struct{}

func (WindowsNetworkBackend) ApplyAction(nm *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData {
	return nm.applyActionWindows(req)
}

func (WindowsNetworkBackend) RollbackAction(nm *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData {
	return nm.rollbackActionWindows(req)
}

func (nm *NetworkManager) applyActionWindows(req protocol.NetworkActionData) protocol.NetworkResultData {
	result := protocol.NetworkResultData{RequestID: req.RequestID}

	method, err := ResolveWindowsNetworkMethod(req.Method)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if method != "netsh" {
		result.Error = fmt.Sprintf("unsupported method %q", method)
		return result
	}

	iface, err := ResolveWindowsNetworkInterface(req.Connection)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	snapshot, snapshotErr := CaptureWindowsNetworkSnapshot(iface)
	if snapshotErr != nil {
		result.Error = fmt.Sprintf("failed to snapshot network state: %v", snapshotErr)
		return result
	}
	result.RollbackReference = snapshot.InterfaceName

	nm.mu.Lock()
	nm.LastMethod = "netsh"
	nm.LastWindowsSnapshot = CloneWindowsNetworkSnapshot(snapshot)
	nm.LastNetplanBackup = ""
	nm.LastNMConnections = nil
	nm.mu.Unlock()

	action := strings.ToLower(strings.TrimSpace(req.Action))
	var applyErr error
	var out []byte

	// Determine sub-action: "dhcp", "static", or "dns" based on connection
	// field convention.  Callers encode the sub-action as a suffix separated
	// by ":" e.g. "Ethernet:dhcp" or "Ethernet:static:192.168.1.10:255.255.255.0:192.168.1.1".
	// When no sub-action is given the backend defaults to triggering DHCP.
	_ = action
	parts := strings.SplitN(req.Connection, ":", 6)
	subAction := "dhcp"
	if len(parts) >= 2 {
		subAction = strings.ToLower(strings.TrimSpace(parts[1]))
	}

	switch subAction {
	case "dhcp":
		out, applyErr = WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
			"netsh", "interface", "ip", "set", "address", iface, "dhcp")
		result.Output = TruncateCommandOutput(out, MaxCommandOutputBytes)
		if applyErr != nil {
			result.Error = fmt.Sprintf("netsh set dhcp failed: %v", applyErr)
			return result
		}

	case "static":
		// parts: [iface, "static", ip, mask, gateway]
		if len(parts) < 4 {
			result.Error = "static sub-action requires ip and mask (format: iface:static:ip:mask[:gateway])"
			return result
		}
		ip := strings.TrimSpace(parts[2])
		mask := strings.TrimSpace(parts[3])
		gateway := ""
		if len(parts) >= 5 {
			gateway = strings.TrimSpace(parts[4])
		}

		netshArgs := []string{"interface", "ip", "set", "address", iface, "static", ip, mask}
		if gateway != "" {
			netshArgs = append(netshArgs, gateway)
		}
		out, applyErr = WindowsRunCommandWithTimeout(NetworkActionCommandTimeout, "netsh", netshArgs...)
		result.Output = TruncateCommandOutput(out, MaxCommandOutputBytes)
		if applyErr != nil {
			result.Error = fmt.Sprintf("netsh set static failed: %v", applyErr)
			return result
		}

	case "dns":
		// parts: [iface, "dns", server1, server2, ...]
		if len(parts) < 3 {
			result.Error = "dns sub-action requires at least one DNS server (format: iface:dns:server1[:server2...])"
			return result
		}
		primaryDNS := strings.TrimSpace(parts[2])
		out, applyErr = WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
			"netsh", "interface", "ip", "set", "dnsservers", iface, "static", primaryDNS, "primary")
		result.Output = TruncateCommandOutput(out, MaxCommandOutputBytes)
		if applyErr != nil {
			result.Error = fmt.Sprintf("netsh set primary DNS failed: %v", applyErr)
			return result
		}

		// Set additional DNS servers (index 2+).
		for i := 3; i < len(parts); i++ {
			server := strings.TrimSpace(parts[i])
			if server == "" {
				continue
			}
			addOut, addErr := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
				"netsh", "interface", "ip", "add", "dnsservers", iface, server, fmt.Sprintf("index=%d", i-1))
			trimmed := TruncateCommandOutput(addOut, MaxCommandOutputBytes)
			if trimmed != "" {
				if result.Output != "" {
					result.Output += "\n"
				}
				result.Output += trimmed
			}
			if addErr != nil && applyErr == nil {
				applyErr = fmt.Errorf("netsh add DNS server %s failed: %v", server, addErr)
			}
		}
		if applyErr != nil {
			result.Error = applyErr.Error()
			return result
		}

	default:
		result.Error = fmt.Sprintf("unsupported sub-action %q: must be dhcp, static, or dns", subAction)
		return result
	}

	if verifyErr := VerifyWindowsConnectivity(req.VerifyTarget); verifyErr != nil {
		rollbackOutput, rollbackErr := nm.rollbackWindowsNetsh()
		result.RollbackAttempted = true
		result.RollbackOutput = rollbackOutput
		result.RollbackSucceeded = rollbackErr == nil
		if rollbackErr != nil {
			result.Error = fmt.Sprintf("connectivity verification failed (%v); rollback failed: %v", verifyErr, rollbackErr)
			return result
		}
		result.Error = fmt.Sprintf("connectivity verification failed (%v); rollback applied", verifyErr)
		return result
	}

	result.OK = true
	return result
}

func (nm *NetworkManager) rollbackActionWindows(req protocol.NetworkActionData) protocol.NetworkResultData {
	result := protocol.NetworkResultData{RequestID: req.RequestID}

	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method == "" || method == "auto" {
		nm.mu.Lock()
		method = nm.LastMethod
		nm.mu.Unlock()
	}
	if method == "" {
		result.Error = "no rollback snapshot is available yet"
		return result
	}
	if method != "netsh" {
		result.Error = fmt.Sprintf("invalid rollback method %q", method)
		return result
	}

	result.RollbackAttempted = true
	output, err := nm.rollbackWindowsNetsh()
	result.RollbackOutput = output
	result.RollbackSucceeded = err == nil
	result.OK = err == nil
	nm.mu.Lock()
	if nm.LastWindowsSnapshot != nil {
		result.RollbackReference = nm.LastWindowsSnapshot.InterfaceName
	}
	nm.mu.Unlock()
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func (nm *NetworkManager) rollbackWindowsNetsh() (string, error) {
	nm.mu.Lock()
	snapshot := CloneWindowsNetworkSnapshot(nm.LastWindowsSnapshot)
	nm.mu.Unlock()

	if snapshot == nil {
		return "", errors.New("no netsh snapshot is available")
	}

	iface := snapshot.InterfaceName
	var parts []string
	var firstErr error

	// Restore IP configuration.
	if snapshot.WasDHCP {
		out, err := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
			"netsh", "interface", "ip", "set", "address", iface, "dhcp")
		trimmed := TruncateCommandOutput(out, MaxCommandOutputBytes)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore DHCP on %s: %w", iface, err)
		}
	} else if snapshot.StaticIP != "" {
		netshArgs := []string{"interface", "ip", "set", "address", iface, "static",
			snapshot.StaticIP, snapshot.SubnetMask}
		if snapshot.Gateway != "" {
			netshArgs = append(netshArgs, snapshot.Gateway)
		}
		out, err := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout, "netsh", netshArgs...)
		trimmed := TruncateCommandOutput(out, MaxCommandOutputBytes)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore static IP on %s: %w", iface, err)
		}
	}

	// Restore DNS configuration.
	restoreDNSWithDHCP := snapshot.DNSWasDHCP || (!snapshot.DNSModeKnown && len(snapshot.DNSServers) == 0)
	if restoreDNSWithDHCP {
		out, err := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
			"netsh", "interface", "ip", "set", "dnsservers", iface, "dhcp")
		trimmed := TruncateCommandOutput(out, MaxCommandOutputBytes)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore DNS to DHCP on %s: %w", iface, err)
		}
	} else {
		out, err := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
			"netsh", "interface", "ip", "set", "dnsservers", iface, "static",
			snapshot.DNSServers[0], "primary")
		trimmed := TruncateCommandOutput(out, MaxCommandOutputBytes)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore primary DNS on %s: %w", iface, err)
		}

		for i := 1; i < len(snapshot.DNSServers); i++ {
			addOut, addErr := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
				"netsh", "interface", "ip", "add", "dnsservers", iface,
				snapshot.DNSServers[i], fmt.Sprintf("index=%d", i+1))
			trimmed = TruncateCommandOutput(addOut, MaxCommandOutputBytes)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
			if addErr != nil && firstErr == nil {
				firstErr = fmt.Errorf("restore DNS server %s on %s: %w", snapshot.DNSServers[i], iface, addErr)
			}
		}
	}

	return strings.Join(parts, "\n"), firstErr
}

// ResolveWindowsNetworkMethod normalises the requested method string and
// validates it for Windows.
func ResolveWindowsNetworkMethod(raw string) (string, error) {
	method := strings.ToLower(strings.TrimSpace(raw))
	switch method {
	case "", "auto", "netsh":
		return "netsh", nil
	default:
		return "", fmt.Errorf("invalid method %q: must be auto or netsh", method)
	}
}

// ResolveWindowsNetworkInterface returns the interface name from the
// Connection field.  The Connection field may be just an interface name
// (e.g. "Ethernet") or the colon-prefixed sub-action form
// (e.g. "Ethernet:dhcp").  When empty, the first connected adapter is
// returned by querying Get-NetAdapter via PowerShell.
func ResolveWindowsNetworkInterface(raw string) (string, error) {
	// Extract interface name: first segment before any colon.
	iface := strings.TrimSpace(raw)
	if idx := strings.Index(iface, ":"); idx >= 0 {
		iface = strings.TrimSpace(iface[:idx])
	}
	if iface != "" {
		return iface, nil
	}

	adapters, err := ListWindowsNetAdapters()
	if err != nil {
		return "", err
	}
	for _, a := range adapters {
		if strings.EqualFold(a.Status, "Up") {
			return a.Name, nil
		}
	}
	if len(adapters) > 0 {
		return adapters[0].Name, nil
	}
	return "", errors.New("no network adapter found")
}

func normalizeNetshSubnetMask(raw string) string {
	value := strings.TrimSpace(raw)
	lower := strings.ToLower(value)
	if marker := strings.Index(lower, "(mask "); marker >= 0 {
		mask := strings.TrimSpace(value[marker+len("(mask "):])
		mask = strings.TrimSuffix(mask, ")")
		if net.ParseIP(mask).To4() != nil {
			return mask
		}
	}
	if net.ParseIP(value).To4() != nil {
		return value
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		return net.IP(network.Mask).String()
	}
	return ""
}

// NetAdapterEntry represents one object from Get-NetAdapter | ConvertTo-Json.
type NetAdapterEntry struct {
	Name                 string `json:"Name"`
	InterfaceDescription string `json:"InterfaceDescription"`
	InterfaceIndex       int    `json:"InterfaceIndex"`
	MacAddress           string `json:"MacAddress"`
	Status               string `json:"Status"`
	LinkSpeed            int64  `json:"LinkSpeed"`
	MediaConnectionState string `json:"MediaConnectionState"`
	IfIndex              int    `json:"ifIndex"`
	DriverDescription    string `json:"DriverDescription"`
}

// parseGetNetAdapterOutput parses the JSON array produced by PowerShell's
// Get-NetAdapter | ConvertTo-Json.
func parseGetNetAdapterOutput(data []byte) ([]NetAdapterEntry, error) {
	// PowerShell may return a single object (not array) when there is only
	// one adapter.  Detect and normalise.
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, errors.New("Get-NetAdapter output is empty")
	}

	if strings.HasPrefix(trimmed, "{") {
		// Single object — wrap in an array.
		var single NetAdapterEntry
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil, fmt.Errorf("parse single Get-NetAdapter object: %w", err)
		}
		return []NetAdapterEntry{single}, nil
	}

	var adapters []NetAdapterEntry
	if err := json.Unmarshal([]byte(trimmed), &adapters); err != nil {
		return nil, fmt.Errorf("parse Get-NetAdapter array: %w", err)
	}
	return adapters, nil
}

// ListWindowsNetAdapters runs Get-NetAdapter via PowerShell and returns the
// parsed adapter list.
var ListWindowsNetAdapters = listWindowsNetAdapters

func listWindowsNetAdapters() ([]NetAdapterEntry, error) {
	out, err := WindowsRunCommandWithTimeout(NetworkActionCommandTimeout,
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetAdapter | ConvertTo-Json")
	if err != nil {
		trimmed := TruncateCommandOutput(out, MaxCommandOutputBytes)
		if trimmed == "" {
			return nil, fmt.Errorf("Get-NetAdapter failed: %w", err)
		}
		return nil, fmt.Errorf("Get-NetAdapter failed: %s", trimmed)
	}
	return parseGetNetAdapterOutput(out)
}

// VerifyWindowsConnectivity pings the target host to verify network
// reachability after a configuration change.
func VerifyWindowsConnectivity(rawTarget string) error {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		target = DefaultConnectivityProbeHost
	}
	if !HasCommand("ping") {
		return nil
	}
	out, err := WindowsRunCommandWithTimeout(NetworkConnectivityTimeout,
		"ping", "-n", "1", "-w", "2000", target)
	if err != nil {
		trimmed := TruncateCommandOutput(out, MaxCommandOutputBytes)
		if trimmed == "" {
			return fmt.Errorf("ping %s failed: %w", target, err)
		}
		return fmt.Errorf("ping %s failed: %s", target, trimmed)
	}
	return nil
}
