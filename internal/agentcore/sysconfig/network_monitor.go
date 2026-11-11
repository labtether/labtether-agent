package sysconfig

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// NetworkMonitor periodically checks local IP addresses and signals OnChange
// when they differ from the previous check. This detects WiFi switches,
// VPN toggles, and sleep/wake network changes.
type NetworkMonitor struct {
	OnChange chan struct{}
	Interval time.Duration
	mu       sync.Mutex
	GetIPs   func() string // injectable for testing
}

func NewNetworkMonitor(onChange chan struct{}) *NetworkMonitor {
	return &NetworkMonitor{
		OnChange: onChange,
		Interval: 30 * time.Second,
		GetIPs:   func() string { return GetHostNetworkIPs() },
	}
}

func (m *NetworkMonitor) Run(ctx context.Context) {
	m.mu.Lock()
	getIPs := m.GetIPs
	m.mu.Unlock()

	lastIPs := getIPs()
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			getIPs = m.GetIPs
			m.mu.Unlock()

			currentIPs := getIPs()
			if currentIPs != lastIPs {
				log.Printf("agentws: network change detected (was=%q, now=%q)", lastIPs, currentIPs)
				lastIPs = currentIPs
				select {
				case m.OnChange <- struct{}{}:
				default:
				}
			}
		}
	}
}

// GetLocalIPs returns a sorted, comma-separated string of all non-loopback
// unicast IP addresses. Used to detect network changes.
func GetLocalIPs() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var ips []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.IsGlobalUnicast() {
			ips = append(ips, ipNet.IP.String())
		}
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
}

// containerBridgeInterface reports whether name is a bridge or veth that a
// container runtime adds and removes as its networks come and go (docker0,
// br-…, veth…). Those are not a change of the host's own network: treating
// them as one made `docker compose up` (which creates a network) reconnect
// the agent and cancel the Compose action that was still running.
func containerBridgeInterface(name string) bool {
	return name == "docker0" || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth")
}

// interfaceAddrs is the interface list the monitor reads (replaceable in tests).
var interfaceAddrs = func() (map[string][]net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]net.Addr, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err == nil {
			out[iface.Name] = addrs
		}
	}
	return out, nil
}

// GetHostNetworkIPs is GetLocalIPs without container runtime bridges: the
// host's own non-loopback unicast addresses, sorted and comma-separated.
func GetHostNetworkIPs() string {
	byInterface, err := interfaceAddrs()
	if err != nil {
		return GetLocalIPs()
	}
	var ips []string
	for name, addrs := range byInterface {
		if containerBridgeInterface(name) {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.IsGlobalUnicast() {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
}
