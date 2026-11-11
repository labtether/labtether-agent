package sysconfig

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetLocalIPs(t *testing.T) {
	t.Parallel()
	ips := GetLocalIPs()
	if ips == "" {
		t.Skip("no non-loopback network interfaces available")
	}
	t.Logf("detected local IPs: %s", ips)
}

func TestNetworkMonitorDetectsChange(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := make(chan struct{}, 1)
	var ipValue atomic.Value
	ipValue.Store("192.168.1.1")

	mon := &NetworkMonitor{
		OnChange: ch,
		Interval: 50 * time.Millisecond,
		GetIPs:   func() string { return ipValue.Load().(string) },
	}

	go mon.Run(ctx)

	// Let it do one tick with the initial value.
	time.Sleep(80 * time.Millisecond)

	// Change the IP.
	ipValue.Store("10.0.0.5")

	select {
	case <-ch:
		// Got change notification — success.
	case <-ctx.Done():
		t.Fatal("timeout waiting for network change notification")
	}
}

func TestNetworkMonitorNoFalsePositive(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := make(chan struct{}, 1)
	mon := &NetworkMonitor{
		OnChange: ch,
		Interval: 50 * time.Millisecond,
		GetIPs:   func() string { return "192.168.1.1" },
	}

	go mon.Run(ctx)

	select {
	case <-ch:
		t.Fatal("got unexpected network change notification")
	case <-ctx.Done():
		// No false positive — success.
	}
}

// `docker compose up` creates a bridge network (br-…); the monitor took it for
// a network change, reconnected the agent and cancelled the running Compose
// action. Container bridges must not count; the host's own addresses must.
func TestHostNetworkIPsIgnoreContainerBridges(t *testing.T) {
	original := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = original })
	ipNet := func(cidr string) net.Addr { ip, n, _ := net.ParseCIDR(cidr); n.IP = ip; return n }
	host := map[string][]net.Addr{
		"eth0":    {ipNet("10.213.71.2/24")},
		"docker0": {ipNet("172.17.0.1/16")},
		"lo":      {ipNet("127.0.0.1/8")},
	}
	interfaceAddrs = func() (map[string][]net.Addr, error) { return host, nil }
	before := GetHostNetworkIPs()
	host["br-0123456789ab"] = []net.Addr{ipNet("172.18.0.1/16")}
	host["veth1234"] = []net.Addr{ipNet("169.254.1.2/16")}
	if after := GetHostNetworkIPs(); after != before || before != "10.213.71.2" {
		t.Fatalf("container bridges changed the host addresses: before=%q after=%q", before, after)
	}
	host["wlan0"] = []net.Addr{ipNet("192.0.2.10/24")}
	if after := GetHostNetworkIPs(); after == before {
		t.Fatal("a new host interface must still count as a network change")
	}
}
