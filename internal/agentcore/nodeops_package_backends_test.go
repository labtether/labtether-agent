package agentcore

import (
	"context"
	"errors"
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/protocol"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestDetectLinuxPackageManagerPrefersSupportedOrder(t *testing.T) {
	originalLookPath := backends.LinuxPackageLookPath
	t.Cleanup(func() {
		backends.LinuxPackageLookPath = originalLookPath
	})

	backends.LinuxPackageLookPath = func(name string) (string, error) {
		switch name {
		case "apt-get", "dnf":
			return "/usr/bin/" + name, nil
		default:
			return "", exec.ErrNotFound
		}
	}

	manager, err := backends.DetectLinuxPackageManager()
	if err != nil {
		t.Fatalf("detectLinuxPackageManager returned error: %v", err)
	}
	if manager != "apt-get" {
		t.Fatalf("manager=%q, want apt-get", manager)
	}
}

func TestLinuxPackageBackendListPackagesSelectsAvailableInventorySource(t *testing.T) {
	originalLookPath := backends.LinuxPackageLookPath
	originalDpkgLister := backends.LinuxPackageDpkgLister
	originalRPMLister := backends.LinuxPackageRPMLister
	t.Cleanup(func() {
		backends.LinuxPackageLookPath = originalLookPath
		backends.LinuxPackageDpkgLister = originalDpkgLister
		backends.LinuxPackageRPMLister = originalRPMLister
	})

	t.Run("prefers dpkg", func(t *testing.T) {
		backends.LinuxPackageLookPath = func(name string) (string, error) {
			switch name {
			case "dpkg-query", "rpm":
				return "/usr/bin/" + name, nil
			default:
				return "", exec.ErrNotFound
			}
		}
		backends.LinuxPackageDpkgLister = func() ([]protocol.PackageInfo, error) {
			return []protocol.PackageInfo{{Name: "jq"}}, nil
		}
		backends.LinuxPackageRPMLister = func() ([]protocol.PackageInfo, error) {
			t.Fatal("expected rpm lister not to be called")
			return nil, nil
		}

		packages, err := backends.LinuxPackageBackend{}.ListPackages()
		if err != nil {
			t.Fatalf("ListPackages returned error: %v", err)
		}
		if len(packages) != 1 || packages[0].Name != "jq" {
			t.Fatalf("unexpected packages %+v", packages)
		}
	})

	t.Run("falls back to rpm", func(t *testing.T) {
		backends.LinuxPackageLookPath = func(name string) (string, error) {
			switch name {
			case "rpm":
				return "/usr/bin/rpm", nil
			default:
				return "", exec.ErrNotFound
			}
		}
		backends.LinuxPackageDpkgLister = func() ([]protocol.PackageInfo, error) {
			t.Fatal("expected dpkg lister not to be called")
			return nil, nil
		}
		backends.LinuxPackageRPMLister = func() ([]protocol.PackageInfo, error) {
			return []protocol.PackageInfo{{Name: "podman"}}, nil
		}

		packages, err := backends.LinuxPackageBackend{}.ListPackages()
		if err != nil {
			t.Fatalf("ListPackages returned error: %v", err)
		}
		if len(packages) != 1 || packages[0].Name != "podman" {
			t.Fatalf("unexpected packages %+v", packages)
		}
	})

	t.Run("returns unsupported when no manager exists", func(t *testing.T) {
		backends.LinuxPackageLookPath = func(string) (string, error) {
			return "", exec.ErrNotFound
		}

		_, err := backends.LinuxPackageBackend{}.ListPackages()
		if !errors.Is(err, backends.ErrNoLinuxPackageManager) {
			t.Fatalf("error=%v, want backends.ErrNoLinuxPackageManager", err)
		}
	})
}

func TestLinuxPackageBackendPerformActionRunsCommandsAndAggregatesOutput(t *testing.T) {
	originalDetectManager := backends.DetectLinuxPackageManagerFn
	originalBuildCommands := backends.BuildLinuxPackageActionCommandsFn
	originalRunCommand := backends.RunLinuxPackageCommand
	originalRebootRequired := backends.DetectLinuxRebootRequiredFn
	t.Cleanup(func() {
		backends.DetectLinuxPackageManagerFn = originalDetectManager
		backends.BuildLinuxPackageActionCommandsFn = originalBuildCommands
		backends.RunLinuxPackageCommand = originalRunCommand
		backends.DetectLinuxRebootRequiredFn = originalRebootRequired
	})

	backends.DetectLinuxPackageManagerFn = func() (string, error) { return "apt-get", nil }
	backends.BuildLinuxPackageActionCommandsFn = func(manager, action string, packages []string) ([]backends.PackageActionCommand, error) {
		if manager != "apt-get" || action != "install" || !reflect.DeepEqual(packages, []string{"jq"}) {
			t.Fatalf("unexpected command build inputs manager=%q action=%q packages=%v", manager, action, packages)
		}
		return []backends.PackageActionCommand{
			{Name: "apt-get", Args: []string{"update"}},
			{Name: "apt-get", Args: []string{"-y", "install", "jq"}},
		}, nil
	}

	var calls []string
	backends.RunLinuxPackageCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "update" {
			return []byte("metadata refreshed"), nil
		}
		return []byte("package installed"), nil
	}
	backends.DetectLinuxRebootRequiredFn = func() bool { return true }

	result, err := backends.LinuxPackageBackend{}.PerformAction("install", []string{"jq"})
	if err != nil {
		t.Fatalf("PerformAction returned error: %v", err)
	}
	if got, want := calls, []string{"apt-get update", "apt-get -y install jq"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("calls=%v, want %v", got, want)
	}
	if result.Output != "metadata refreshed\npackage installed" {
		t.Fatalf("output=%q, want metadata refreshed\\npackage installed", result.Output)
	}
	if !result.RebootRequired {
		t.Fatal("expected reboot_required=true")
	}
}

func TestLinuxPackageBackendPerformActionReturnsTimeoutWithPartialOutput(t *testing.T) {
	originalDetectManager := backends.DetectLinuxPackageManagerFn
	originalBuildCommands := backends.BuildLinuxPackageActionCommandsFn
	originalRunCommand := backends.RunLinuxPackageCommand
	originalRebootRequired := backends.DetectLinuxRebootRequiredFn
	t.Cleanup(func() {
		backends.DetectLinuxPackageManagerFn = originalDetectManager
		backends.BuildLinuxPackageActionCommandsFn = originalBuildCommands
		backends.RunLinuxPackageCommand = originalRunCommand
		backends.DetectLinuxRebootRequiredFn = originalRebootRequired
	})

	backends.DetectLinuxPackageManagerFn = func() (string, error) { return "apt-get", nil }
	backends.BuildLinuxPackageActionCommandsFn = func(string, string, []string) ([]backends.PackageActionCommand, error) {
		return []backends.PackageActionCommand{{Name: "apt-get", Args: []string{"upgrade"}}}, nil
	}
	backends.RunLinuxPackageCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("slow output"), context.DeadlineExceeded
	}
	backends.DetectLinuxRebootRequiredFn = func() bool { return false }

	result, err := backends.LinuxPackageBackend{}.PerformAction("upgrade", nil)
	if err == nil || err.Error() != "package action timed out" {
		t.Fatalf("error=%v, want package action timed out", err)
	}
	if result.Output != "slow output" {
		t.Fatalf("output=%q, want slow output", result.Output)
	}
}
