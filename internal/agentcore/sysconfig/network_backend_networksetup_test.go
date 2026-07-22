package sysconfig

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestResolveDarwinNetworkMethodWith(t *testing.T) {
	commandExists := func(name string) bool { return name == "networksetup" }

	method, err := ResolveDarwinNetworkMethodWith("auto", commandExists)
	if err != nil {
		t.Fatalf("ResolveDarwinNetworkMethodWith returned error: %v", err)
	}
	if method != "networksetup" {
		t.Fatalf("method=%q, want networksetup", method)
	}

	if _, err := ResolveDarwinNetworkMethodWith("nmcli", commandExists); err == nil {
		t.Fatal("expected invalid-method error")
	}
}

func TestParseDarwinNetworkServicesOutput(t *testing.T) {
	raw := `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*USB 10/100/1000 LAN
Thunderbolt Bridge`

	services := ParseDarwinNetworkServicesOutput(raw)
	if len(services) != 3 {
		t.Fatalf("len(services)=%d, want 3", len(services))
	}
	if services[0].Name != "Wi-Fi" || services[0].Disabled {
		t.Fatalf("unexpected first service: %+v", services[0])
	}
	if services[1].Name != "USB 10/100/1000 LAN" || !services[1].Disabled {
		t.Fatalf("unexpected second service: %+v", services[1])
	}
}

func TestParseDarwinDNSServersOutput(t *testing.T) {
	servers, hasDNS := ParseDarwinDNSServersOutput("8.8.8.8\n1.1.1.1\n")
	if !hasDNS {
		t.Fatal("expected hasDNS=true")
	}
	wantServers := []string{"8.8.8.8", "1.1.1.1"}
	if !reflect.DeepEqual(servers, wantServers) {
		t.Fatalf("servers=%v, want %v", servers, wantServers)
	}

	none, hasDNS := ParseDarwinDNSServersOutput("There aren't any DNS Servers set on Wi-Fi.\n")
	if hasDNS {
		t.Fatal("expected hasDNS=false when DNS is unset")
	}
	if len(none) != 0 {
		t.Fatalf("expected no DNS servers, got %v", none)
	}
}

func TestParseDarwinNetworkServiceEnabledOutput(t *testing.T) {
	enabled, ok := ParseDarwinNetworkServiceEnabledOutput("Enabled")
	if !ok || !enabled {
		t.Fatalf("expected enabled=true, ok=true; got enabled=%v ok=%v", enabled, ok)
	}

	enabled, ok = ParseDarwinNetworkServiceEnabledOutput("Disabled")
	if !ok || enabled {
		t.Fatalf("expected enabled=false, ok=true; got enabled=%v ok=%v", enabled, ok)
	}
}

func TestApplyActionDarwinFailsClosedWhenEnabledStateSnapshotFails(t *testing.T) {
	originalRunner := DarwinNetworkRunCommandWithTimeout
	originalHasCommand := DarwinNetworkHasCommand
	defer func() {
		DarwinNetworkRunCommandWithTimeout = originalRunner
		DarwinNetworkHasCommand = originalHasCommand
	}()

	DarwinNetworkHasCommand = func(name string) bool { return name == "networksetup" }
	mutatingCalls := 0
	DarwinNetworkRunCommandWithTimeout = func(_ time.Duration, name string, args ...string) ([]byte, error) {
		if name != "networksetup" || len(args) == 0 {
			return nil, errors.New("unexpected command")
		}
		switch args[0] {
		case "-getdnsservers":
			return []byte("1.1.1.1\n"), nil
		case "-getnetworkserviceenabled":
			return []byte("permission denied"), errors.New("exit status 1")
		case "-setnetworkserviceenabled", "-setdnsservers":
			mutatingCalls++
			return nil, nil
		default:
			return nil, errors.New("unexpected networksetup arguments")
		}
	}

	nm := &NetworkManager{}
	result := nm.applyActionDarwin(protocol.NetworkActionData{
		RequestID:  "darwin-fail-closed",
		Method:     "networksetup",
		Connection: "Wi-Fi",
	})
	if result.OK {
		t.Fatal("expected apply to fail when enabled-state snapshot fails")
	}
	if !strings.Contains(result.Error, "failed to snapshot network state") ||
		!strings.Contains(result.Error, "capture network service enabled state") {
		t.Fatalf("error=%q, want enabled-state snapshot failure", result.Error)
	}
	if mutatingCalls != 0 {
		t.Fatalf("mutating networksetup calls=%d, want 0", mutatingCalls)
	}
	if nm.LastDarwinSnapshot != nil || nm.LastMethod != "" {
		t.Fatalf("manager retained incomplete snapshot: method=%q snapshot=%+v", nm.LastMethod, nm.LastDarwinSnapshot)
	}
}

func TestRollbackDarwinFailsClosedWithoutEnabledState(t *testing.T) {
	originalRunner := DarwinNetworkRunCommandWithTimeout
	defer func() { DarwinNetworkRunCommandWithTimeout = originalRunner }()

	commandCalls := 0
	DarwinNetworkRunCommandWithTimeout = func(_ time.Duration, _ string, _ ...string) ([]byte, error) {
		commandCalls++
		return nil, nil
	}

	nm := &NetworkManager{
		LastDarwinSnapshot: &DarwinNetworkSnapshot{
			Service:         "Wi-Fi",
			DNSServers:      []string{"1.1.1.1"},
			HasDNSServers:   true,
			HasEnabledState: false,
		},
	}
	if _, err := nm.rollbackDarwinNetworkSetup(); err == nil || !strings.Contains(err.Error(), "missing the service enabled state") {
		t.Fatalf("rollback error=%v, want incomplete snapshot failure", err)
	}
	if commandCalls != 0 {
		t.Fatalf("rollback command calls=%d, want 0", commandCalls)
	}
}
