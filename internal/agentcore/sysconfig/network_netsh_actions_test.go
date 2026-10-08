package sysconfig

import (
	"errors"
	"github.com/labtether/protocol"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// WindowsNetworkBackend ApplyAction / RollbackAction — unit-level with stubs
// ---------------------------------------------------------------------------

// stubWindowsRun replaces WindowsRunCommandWithTimeout for the duration of fn.
// It records each call and feeds back outputs/errors in sequence.
func stubWindowsRun(outputs [][]byte, errs []error, fn func()) [][]string {
	orig := WindowsRunCommandWithTimeout
	var calls [][]string
	idx := 0
	WindowsRunCommandWithTimeout = func(_ time.Duration, name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		var out []byte
		var err error
		if idx < len(outputs) {
			out = outputs[idx]
		}
		if idx < len(errs) {
			err = errs[idx]
		}
		idx++
		return out, err
	}
	defer func() { WindowsRunCommandWithTimeout = orig }()
	fn()
	return calls
}

func TestWindowsNetworkBackend_ApplyDHCP(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}

	outputs := [][]byte{
		// CaptureWindowsNetworkSnapshot: show config
		[]byte("    DHCP enabled:                         No\n    IP Address:                           10.0.0.5\n    Subnet Prefix:                        10.0.0.0/24 (mask 255.255.255.0)\n    Default Gateway:                      10.0.0.1\n"),
		// CaptureWindowsNetworkSnapshot: show dnsservers
		[]byte("    Statically Configured DNS Servers:    8.8.8.8\n"),
		// Apply: netsh interface ip set address ... dhcp
		[]byte("Ok.\n"),
		// VerifyWindowsConnectivity: ping (success)
		[]byte("Reply from 1.1.1.1: bytes=32\n"),
	}
	errs := make([]error, len(outputs))

	req := protocol.NetworkActionData{
		RequestID:  "req-1",
		Action:     "apply",
		Connection: "Ethernet:dhcp",
	}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, errs, func() {
		result = backend.ApplyAction(nm, req)
	})

	if !result.OK {
		t.Errorf("expected OK=true, got error: %s", result.Error)
	}
	if result.RequestID != "req-1" {
		t.Errorf("RequestID=%q, want req-1", result.RequestID)
	}
	if result.RollbackReference != "Ethernet" {
		t.Errorf("RollbackReference=%q, want Ethernet", result.RollbackReference)
	}

	// Verify the DHCP apply command was issued.
	foundDHCP := false
	for _, c := range calls {
		if len(c) >= 7 && c[0] == "netsh" && c[len(c)-1] == "dhcp" {
			foundDHCP = true
		}
	}
	if !foundDHCP {
		t.Errorf("expected netsh ... dhcp call; calls=%v", calls)
	}

	// Verify snapshot was saved.
	nm.mu.Lock()
	snap := nm.LastWindowsSnapshot
	nm.mu.Unlock()
	if snap == nil {
		t.Fatal("LastWindowsSnapshot should not be nil after apply")
	}
	if snap.InterfaceName != "Ethernet" {
		t.Errorf("snapshot.InterfaceName=%q, want Ethernet", snap.InterfaceName)
	}
}

func TestWindowsNetworkBackend_DNSSnapshotFailurePreventsApply(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}

	outputs := [][]byte{
		[]byte("    DHCP enabled:                         Yes\n"),
		[]byte("Access is denied.\n"),
	}
	errs := []error{nil, errors.New("exit status 1")}
	req := protocol.NetworkActionData{
		RequestID:  "req-dns-snapshot-failure",
		Action:     "apply",
		Connection: "Ethernet:dhcp",
	}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, errs, func() {
		result = backend.ApplyAction(nm, req)
	})

	if result.OK {
		t.Fatal("expected snapshot failure to prevent network apply")
	}
	if !strings.Contains(result.Error, "failed to snapshot network state") ||
		!strings.Contains(result.Error, "dnsservers") {
		t.Fatalf("unexpected error: %q", result.Error)
	}
	if len(calls) != 2 {
		t.Fatalf("expected only IP and DNS snapshot calls, got %v", calls)
	}
	for _, call := range calls {
		if strings.Contains(strings.Join(call, " "), " set ") {
			t.Fatalf("network mutation was attempted after incomplete snapshot: %v", calls)
		}
	}
	if nm.LastWindowsSnapshot != nil {
		t.Fatal("incomplete snapshot must not be persisted for rollback")
	}
}

func TestWindowsNetworkBackend_LocalizedIPSnapshotFailsClosed(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}
	outputs := [][]byte{[]byte("    DHCP aktiviert:                      Ja\n    IP-Adresse:                          192.168.1.50\n")}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, []error{nil}, func() {
		result = backend.ApplyAction(nm, protocol.NetworkActionData{
			RequestID: "localized-ip", Action: "apply", Connection: "Ethernet:dhcp",
		})
	})
	if result.OK || !strings.Contains(result.Error, "unrecognized or localized DHCP mode") {
		t.Fatalf("expected fail-closed localized snapshot error, got %+v", result)
	}
	if len(calls) != 1 || strings.Contains(strings.Join(calls[0], " "), " set ") {
		t.Fatalf("unexpected calls after unrecognized IP snapshot: %v", calls)
	}
}

func TestWindowsNetworkBackend_LocalizedDNSSnapshotFailsClosed(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}
	outputs := [][]byte{
		[]byte("    DHCP enabled:                         Yes\n"),
		[]byte("    DNS-Server durch DHCP konfiguriert:   192.168.1.1\n"),
	}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, []error{nil, nil}, func() {
		result = backend.ApplyAction(nm, protocol.NetworkActionData{
			RequestID: "localized-dns", Action: "apply", Connection: "Ethernet:dhcp",
		})
	})
	if result.OK || !strings.Contains(result.Error, "unrecognized or localized DNS mode") {
		t.Fatalf("expected fail-closed localized DNS snapshot error, got %+v", result)
	}
	if len(calls) != 2 {
		t.Fatalf("expected only two snapshot calls, got %v", calls)
	}
	for _, call := range calls {
		if strings.Contains(strings.Join(call, " "), " set ") {
			t.Fatalf("network mutation attempted after localized DNS snapshot: %v", calls)
		}
	}
}

func TestWindowsNetworkBackend_RollbackNoSnapshot(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}

	req := protocol.NetworkActionData{
		RequestID: "req-2",
		Action:    "rollback",
	}
	result := backend.RollbackAction(nm, req)

	if result.OK {
		t.Error("expected OK=false when no snapshot exists")
	}
	if result.Error == "" {
		t.Error("expected a non-empty error message")
	}
}

func TestWindowsNetworkBackend_InvalidMethod(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}

	req := protocol.NetworkActionData{
		RequestID:  "req-3",
		Action:     "apply",
		Method:     "nmcli",
		Connection: "Ethernet:dhcp",
	}
	result := backend.ApplyAction(nm, req)

	if result.OK {
		t.Error("expected OK=false for unsupported method")
	}
	if result.Error == "" {
		t.Error("expected error message for unsupported method")
	}
}

func TestWindowsNetworkBackend_StaticSubAction(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}

	outputs := [][]byte{
		// show config
		[]byte("    DHCP enabled:                         Yes\n    IP Address:                           192.168.1.100\n"),
		// show dnsservers
		[]byte("    DNS servers configured through DHCP:  192.168.1.1\n"),
		// netsh set static
		[]byte("Ok.\n"),
		// ping
		[]byte("Reply from 1.1.1.1\n"),
	}
	errs := make([]error, len(outputs))

	req := protocol.NetworkActionData{
		RequestID:  "req-4",
		Action:     "apply",
		Connection: "Ethernet:static:192.168.1.50:255.255.255.0:192.168.1.1",
	}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, errs, func() {
		result = backend.ApplyAction(nm, req)
	})

	if !result.OK {
		t.Errorf("expected OK=true, got error: %s", result.Error)
	}

	foundStatic := false
	for _, c := range calls {
		if len(c) >= 8 && c[0] == "netsh" && c[6] == "static" {
			foundStatic = true
		}
	}
	if !foundStatic {
		t.Errorf("expected netsh ... static call; calls=%v", calls)
	}
}

func TestWindowsNetworkBackend_RollbackWithSnapshot(t *testing.T) {
	nm := &NetworkManager{
		LastMethod: "netsh",
		LastWindowsSnapshot: &WindowsNetworkSnapshot{
			InterfaceName: "Ethernet",
			WasDHCP:       true,
			DNSServers:    []string{"8.8.8.8"},
		},
	}
	backend := WindowsNetworkBackend{}

	outputs := [][]byte{
		// restore DHCP
		[]byte("Ok.\n"),
		// restore primary DNS
		[]byte("Ok.\n"),
	}
	errs := make([]error, len(outputs))

	req := protocol.NetworkActionData{
		RequestID: "req-5",
		Action:    "rollback",
	}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, errs, func() {
		result = backend.RollbackAction(nm, req)
	})

	if !result.OK {
		t.Errorf("expected OK=true, got error: %s", result.Error)
	}
	if !result.RollbackAttempted {
		t.Error("expected RollbackAttempted=true")
	}
	if !result.RollbackSucceeded {
		t.Error("expected RollbackSucceeded=true")
	}
	if result.RollbackReference != "Ethernet" {
		t.Errorf("RollbackReference=%q, want Ethernet", result.RollbackReference)
	}

	// Should have issued netsh set address dhcp and netsh set dnsservers.
	if len(calls) < 2 {
		t.Errorf("expected at least 2 netsh calls; calls=%v", calls)
	}
}

func TestWindowsNetworkBackend_DNSSubAction(t *testing.T) {
	nm := &NetworkManager{}
	backend := WindowsNetworkBackend{}

	outputs := [][]byte{
		// show config
		[]byte("    DHCP enabled:                         Yes\n"),
		// show dnsservers
		[]byte("    DNS servers configured through DHCP:  192.168.1.1\n"),
		// netsh set dnsservers primary
		[]byte("Ok.\n"),
		// ping
		[]byte("Reply from 1.1.1.1\n"),
	}
	errs := make([]error, len(outputs))

	req := protocol.NetworkActionData{
		RequestID:  "req-6",
		Action:     "apply",
		Connection: "Ethernet:dns:8.8.8.8:1.1.1.1",
	}

	var result protocol.NetworkResultData
	calls := stubWindowsRun(outputs, errs, func() {
		result = backend.ApplyAction(nm, req)
	})

	if !result.OK {
		t.Errorf("expected OK=true, got error: %s", result.Error)
	}

	foundDNS := false
	for _, c := range calls {
		if len(c) >= 5 && c[0] == "netsh" && c[4] == "dnsservers" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Errorf("expected netsh dnsservers call; calls=%v", calls)
	}
}
