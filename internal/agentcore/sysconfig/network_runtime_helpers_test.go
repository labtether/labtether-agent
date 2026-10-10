package sysconfig

import (
	"testing"
	"time"

	wire "github.com/labtether/protocol"
)

// A default route alone cannot prove that an applied network still works.
func TestNetworkApplyRejectsMissingConnectivityProbe(t *testing.T) {
	originalHasCommand := NetworkHasCommand
	originalRun := NetworkRunCommandWithTimeout
	originalResolve := ResolveNetworkMethodFn
	originalBackup := BackupNetplanConfigFn
	t.Cleanup(func() {
		NetworkHasCommand = originalHasCommand
		NetworkRunCommandWithTimeout = originalRun
		ResolveNetworkMethodFn = originalResolve
		BackupNetplanConfigFn = originalBackup
	})
	NetworkHasCommand = func(name string) bool { return name != "ping" }
	NetworkRunCommandWithTimeout = func(time.Duration, string, ...string) ([]byte, error) {
		t.Error("missing connectivity probe must fail before executing a network command")
		return nil, nil
	}
	BackupNetplanConfigFn = func() (string, error) {
		t.Error("missing probe must not consume or create a network snapshot")
		return "", nil
	}
	for _, method := range []string{"netplan", "nmcli"} {
		t.Run(method, func(t *testing.T) {
			ResolveNetworkMethodFn = func(string) (string, error) { return method, nil }
			nm := &NetworkManager{NetplanBaseline: "existing-baseline"}
			result := nm.ApplyActionLinux(wire.NetworkActionData{Action: "apply", Method: method})
			if result.OK || result.Error == "" || result.RollbackAttempted || nm.NetplanBaseline != "existing-baseline" {
				t.Fatalf("network apply did not fail safely before changes: %+v", result)
			}
		})
	}
	if err := VerifyConnectivity("192.0.2.1"); err == nil {
		t.Fatal("missing post-apply probe must report an error so the caller rolls back")
	}
}
