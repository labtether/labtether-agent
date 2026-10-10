package sysconfig

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestConcurrentNetplanApplyConsumesSnapshotOnce(t *testing.T) {
	originalResolve := ResolveNetworkMethodFn
	originalBackup := BackupNetplanConfigFn
	originalRun := NetworkRunCommandWithTimeout
	originalVerify := VerifyNetworkConnectivity
	originalHasCommand := NetworkHasCommand
	t.Cleanup(func() {
		ResolveNetworkMethodFn = originalResolve
		BackupNetplanConfigFn = originalBackup
		NetworkRunCommandWithTimeout = originalRun
		VerifyNetworkConnectivity = originalVerify
		NetworkHasCommand = originalHasCommand
	})
	NetworkHasCommand = func(string) bool { return true }
	ResolveNetworkMethodFn = func(string) (string, error) { return "netplan", nil }
	var backups atomic.Int32
	BackupNetplanConfigFn = func() (string, error) {
		if backups.Add(1) == 1 {
			return "/tmp/netplan-before-edit", nil
		}
		return "/tmp/netplan-staged", nil
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var commands atomic.Int32
	NetworkRunCommandWithTimeout = func(time.Duration, string, ...string) ([]byte, error) {
		if commands.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil, nil
	}
	VerifyNetworkConnectivity = func(string) error { return nil }
	nm := &NetworkManager{Backend: LinuxNetworkBackend{}}
	if err := nm.CaptureNetplanBaseline(); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan protocol.NetworkResultData, 1)
	secondDone := make(chan protocol.NetworkResultData, 1)
	go func() {
		firstDone <- nm.ApplyActionLinux(protocol.NetworkActionData{Action: "apply", Method: "netplan"})
	}()
	<-started
	go func() {
		secondDone <- nm.ApplyActionLinux(protocol.NetworkActionData{Action: "apply", Method: "netplan"})
	}()
	close(release)
	first := <-firstDone
	second := <-secondDone
	if !first.OK || second.OK || !strings.Contains(second.Error, "no pre-change netplan snapshot") || commands.Load() != 1 || backups.Load() != 2 {
		t.Fatalf("one-use snapshot was reused: first=%+v second=%+v commands=%d backups=%d", first, second, commands.Load(), backups.Load())
	}
}
