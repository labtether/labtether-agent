package backends

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

func TestParseLinuxUpgradablePackageInventories(t *testing.T) {
	tests := []struct {
		name string
		run  func() ([]UpgradablePackageInfo, error)
		want []UpgradablePackageInfo
	}{
		{
			name: "apt",
			run: func() ([]UpgradablePackageInfo, error) {
				return ParseAPTUpgradablePackages([]byte("Inst curl [8.5.0-2] (8.6.0-1 Debian:stable [amd64])\nConf curl (8.6.0-1 Debian:stable [amd64])\n"))
			},
			want: []UpgradablePackageInfo{{Name: "curl", Version: "8.5.0-2", AvailableVersion: "8.6.0-1"}},
		},
		{
			name: "dnf",
			run: func() ([]UpgradablePackageInfo, error) {
				return ParseDNFUpgradablePackages(
					[]byte("curl.x86_64 8.6.0-1.el9 updates\n"),
					[]byte("curl.x86_64\t8.5.0-2.el9\n"),
				)
			},
			want: []UpgradablePackageInfo{{Name: "curl.x86_64", Version: "8.5.0-2.el9", AvailableVersion: "8.6.0-1.el9"}},
		},
		{
			name: "zypper",
			run: func() ([]UpgradablePackageInfo, error) {
				return ParseZypperUpgradablePackages([]byte("S | Repository | Name | Current Version | Available Version | Arch\nv | repo | curl | 8.5.0 | 8.6.0 | x86_64\n"))
			},
			want: []UpgradablePackageInfo{{Name: "curl", Version: "8.5.0", AvailableVersion: "8.6.0"}},
		},
		{
			name: "pacman",
			run: func() ([]UpgradablePackageInfo, error) {
				return ParsePacmanUpgradablePackages([]byte("curl 8.5.0-1 -> 8.6.0-1\n"))
			},
			want: []UpgradablePackageInfo{{Name: "curl", Version: "8.5.0-1", AvailableVersion: "8.6.0-1"}},
		},
		{
			name: "apk",
			run: func() ([]UpgradablePackageInfo, error) {
				return ParseAPKUpgradablePackages([]byte("Installed:                              Available:\ncurl-8.5.0-r0                         < 8.6.0-r0\n"))
			},
			want: []UpgradablePackageInfo{{Name: "curl", Version: "8.5.0-r0", AvailableVersion: "8.6.0-r0"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.run()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("packages = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestLinuxUpgradableParsersRejectUnrecognizedOutput(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "apt", run: func() error { _, err := ParseAPTUpgradablePackages([]byte("garbage\n")); return err }},
		{name: "dnf", run: func() error {
			_, err := ParseDNFUpgradablePackages([]byte("garbage\n"), []byte("curl.x86_64\t8.5.0\n"))
			return err
		}},
		{name: "zypper", run: func() error { _, err := ParseZypperUpgradablePackages([]byte("garbage\n")); return err }},
		{name: "pacman", run: func() error { _, err := ParsePacmanUpgradablePackages([]byte("garbage\n")); return err }},
		{name: "apk", run: func() error { _, err := ParseAPKUpgradablePackages([]byte("garbage\n")); return err }},
		{name: "choco", run: func() error { _, err := ParseChocoUpgradablePackages([]byte("garbage\n")); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("unrecognized output was accepted as an empty update inventory")
			}
		})
	}
}

func TestParseAPKUpgradablePackagesAcceptsHeadingOnlyForNoUpdates(t *testing.T) {
	got, err := ParseAPKUpgradablePackages([]byte("Installed:                              Available:\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("packages = %#v, want empty", got)
	}
}

func TestParseAPKUpgradablePackagesAcceptsRepositoryTag(t *testing.T) {
	got, err := ParseAPKUpgradablePackages([]byte("Installed:                              Available:\ncurl-8.5.0-r0                         < 8.6.0-r0 @edge\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []UpgradablePackageInfo{{Name: "curl", Version: "8.5.0-r0", AvailableVersion: "8.6.0-r0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages = %#v, want %#v", got, want)
	}
}

func TestParseAPKUpgradablePackagesRejectsHeadingLookalikes(t *testing.T) {
	for _, input := range []string{
		"",
		"curl-8.5.0-r0 < 8.6.0-r0\n",
		"Installed: Available: unexpected\n",
		"Installed packages Available:\n",
		"Warning: Available:\n",
		"Installed: Available:\nInstalled: Available:\n",
		"curl-8.5.0-r0 < 8.6.0-r0\nInstalled: Available:\n",
		"Installed: Available:\ncurl-8.5.0-r0 < 8.6.0-r0 @\n",
		"Installed: Available:\ncurl-8.5.0-r0 < 8.6.0-r0 edge\n",
		"Installed: Available:\ncurl-8.5.0-r0 < 8.6.0-r0 @edge unexpected\n",
	} {
		if _, err := ParseAPKUpgradablePackages([]byte(input)); err == nil {
			t.Fatalf("heading lookalike %q was accepted", input)
		}
	}
}

func TestLinuxUpgradableInventoryUsesStrictTimeout(t *testing.T) {
	originalDetect := DetectLinuxPackageManagerFn
	originalRun := RunLinuxPackageInventoryCommand
	t.Cleanup(func() {
		DetectLinuxPackageManagerFn = originalDetect
		RunLinuxPackageInventoryCommand = originalRun
	})
	DetectLinuxPackageManagerFn = func() (string, error) { return "apt-get", nil }
	RunLinuxPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("partial"), context.DeadlineExceeded
	}

	_, err := (LinuxPackageBackend{}).ListUpgradablePackages()
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestParseChocoUpgradablePackages(t *testing.T) {
	got, err := ParseChocoUpgradablePackages([]byte("git|2.43.0|2.44.0|false\n7zip|23.01|24.00|false\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []UpgradablePackageInfo{
		{Name: "git", Version: "2.43.0", AvailableVersion: "2.44.0"},
		{Name: "7zip", Version: "23.01", AvailableVersion: "24.00"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages = %#v, want %#v", got, want)
	}
}

func TestWindowsUpgradableInventoryIsBoundedAndTimesOut(t *testing.T) {
	originalRun := RunWindowsPackageInventoryCommand
	t.Cleanup(func() { RunWindowsPackageInventoryCommand = originalRun })

	t.Run("timeout", func(t *testing.T) {
		RunWindowsPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
			return nil, context.DeadlineExceeded
		}
		_, err := (WindowsPackageBackend{backend: "winget"}).ListUpgradablePackages()
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("timeout error = %v", err)
		}
	})

	t.Run("output overflow", func(t *testing.T) {
		RunWindowsPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
			return bytes.Repeat([]byte("x"), 64), fmt.Errorf("%w", securityruntime.ErrCommandOutputLimit)
		}
		_, err := (WindowsPackageBackend{backend: "winget"}).ListUpgradablePackages()
		if err == nil || !strings.Contains(err.Error(), "output exceeded") {
			t.Fatalf("overflow error = %v", err)
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		RunWindowsPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
			return []byte("garbage"), nil
		}
		_, err := (WindowsPackageBackend{backend: "winget"}).ListUpgradablePackages()
		if err == nil || !strings.Contains(err.Error(), "unrecognized") {
			t.Fatalf("malformed output error = %v", err)
		}
	})
}

func TestNormalizeUpgradablePackagesRejectsMalformedAndOversized(t *testing.T) {
	for _, packages := range [][]UpgradablePackageInfo{
		{{Name: "--source", Version: "1", AvailableVersion: "2"}},
		{{Name: "curl", Version: "", AvailableVersion: "2"}},
		{{Name: "curl", Version: "1", AvailableVersion: "2\n3"}},
		{{Name: "curl", Version: strings.Repeat("1", MaxPackageInventoryVersionBytes+1), AvailableVersion: "2"}},
	} {
		if _, err := normalizeUpgradablePackages(packages); err == nil {
			t.Fatalf("malformed inventory was accepted: %#v", packages)
		}
	}

	oversized := make([]UpgradablePackageInfo, MaxPackageInventoryItems+1)
	if _, err := normalizeUpgradablePackages(oversized); err == nil {
		t.Fatal("oversized inventory was accepted")
	}
}

func TestInstalledPackageInventoryValidationIsBoundedAndRegistryCompatible(t *testing.T) {
	if err := validateInstalledPackageInventory([]protocol.PackageInfo{{Name: "Vendor Utility", Status: "installed"}}); err != nil {
		t.Fatalf("registry package without version rejected: %v", err)
	}
	for _, packages := range [][]protocol.PackageInfo{
		{{Name: "", Status: "installed"}},
		{{Name: "curl\n", Version: "1", Status: "installed"}},
		{{Name: "curl", Version: strings.Repeat("1", MaxPackageInventoryVersionBytes+1), Status: "installed"}},
	} {
		if err := validateInstalledPackageInventory(packages); err == nil {
			t.Fatalf("malformed installed inventory accepted: %#v", packages)
		}
	}
	oversized := make([]protocol.PackageInfo, MaxPackageInventoryItems+1)
	if err := validateInstalledPackageInventory(oversized); err == nil {
		t.Fatal("oversized installed inventory accepted")
	}
}

type capturePackageMessageSender struct {
	messages []protocol.Message
}

func (s *capturePackageMessageSender) AssetID() string { return "asset-package-test" }
func (s *capturePackageMessageSender) Connected() bool { return true }

func (s *capturePackageMessageSender) Send(message protocol.Message) error {
	s.messages = append(s.messages, message)
	return nil
}

func TestPackageListedPayloadFailsClosedAboveMessageBudget(t *testing.T) {
	packages := make([]UpgradablePackageInfo, MaxPackageInventoryItems)
	version := strings.Repeat("1", MaxPackageInventoryVersionBytes)
	for index := range packages {
		packages[index] = UpgradablePackageInfo{
			Name:             fmt.Sprintf("pkg-%05d", index),
			Version:          version,
			AvailableVersion: version,
			Status:           PackageInventoryUpgradable,
		}
	}
	sender := &capturePackageMessageSender{}
	manager := &PackageManager{}
	manager.sendPackageListed(sender, packageListedResponseWire{
		RequestID: "req-payload-limit",
		Inventory: PackageInventoryUpgradable,
		Packages:  packages,
	})
	if len(sender.messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(sender.messages))
	}
	if len(sender.messages[0].Data) > MaxPackageInventoryPayloadBytes {
		t.Fatalf("response payload = %d, exceeds %d", len(sender.messages[0].Data), MaxPackageInventoryPayloadBytes)
	}
	var response packageListedResponseWire
	if err := json.Unmarshal(sender.messages[0].Data, &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error == "" || len(response.Packages) != 0 {
		t.Fatalf("oversized payload did not fail closed: %+v", response)
	}
}

func TestPackageInventoryCommandErrorAcceptsManagerNoUpdateExitCodes(t *testing.T) {
	err := packageInventoryCommandError(context.Background(), "dnf", "listing", nil, fakePackageExitError(100), 100)
	if err != nil {
		t.Fatalf("accepted exit code returned error: %v", err)
	}
}

func TestPackageInventoryCommandErrorDoesNotHideOverflowBehindAcceptedExitCode(t *testing.T) {
	err := packageInventoryCommandError(
		context.Background(),
		"dnf",
		"listing",
		nil,
		errors.Join(fakePackageExitError(100), securityruntime.ErrCommandOutputLimit),
		100,
	)
	if err == nil || !strings.Contains(err.Error(), "output exceeded") {
		t.Fatalf("combined overflow error = %v", err)
	}
}

type fakePackageExitError int

func (e fakePackageExitError) Error() string { return "exit" }
func (e fakePackageExitError) ExitCode() int { return int(e) }

func TestPackageInventoryCommandErrorPreservesOrdinaryFailure(t *testing.T) {
	err := packageInventoryCommandError(context.Background(), "apt", "listing", []byte("failure"), errors.New("exit"))
	if err == nil || !strings.Contains(err.Error(), "failure") {
		t.Fatalf("ordinary error = %v", err)
	}
}

func TestSupportedPackageManagersPassExecutablePolicy(t *testing.T) {
	for _, executable := range []string{"apt-get", "dnf", "yum", "zypper", "pacman", "apk", "rpm", "brew", "winget", "choco"} {
		if err := securityruntime.ValidateExecBinary(executable); err != nil {
			t.Fatalf("supported package manager %q rejected by executable policy: %v", executable, err)
		}
	}
}
