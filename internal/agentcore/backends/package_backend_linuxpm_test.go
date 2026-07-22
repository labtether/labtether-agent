package backends

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/labtether/protocol"
)

func TestLinuxPackageActionAggregateOutputIsBounded(t *testing.T) {
	originalDetect := DetectLinuxPackageManagerFn
	originalRun := RunLinuxPackageCommand
	originalReboot := DetectLinuxRebootRequiredFn
	t.Cleanup(func() {
		DetectLinuxPackageManagerFn = originalDetect
		RunLinuxPackageCommand = originalRun
		DetectLinuxRebootRequiredFn = originalReboot
	})

	DetectLinuxPackageManagerFn = func() (string, error) { return "apt-get", nil }
	RunLinuxPackageCommand = func(context.Context, string, ...string) ([]byte, error) {
		return bytes.Repeat([]byte("x"), MaxCommandOutputBytes*4), nil
	}
	DetectLinuxRebootRequiredFn = func() bool { return false }

	result, err := (LinuxPackageBackend{}).PerformAction("remove", []string{"curl"})
	if err != nil {
		t.Fatalf("PerformAction: %v", err)
	}
	if len(result.Output) > MaxCommandOutputBytes+len("\n...output truncated") {
		t.Fatalf("result output length = %d, expected bounded output", len(result.Output))
	}
	if !strings.HasSuffix(result.Output, "...output truncated") {
		t.Fatalf("result output did not report truncation (length %d)", len(result.Output))
	}
}

func TestBuildLinuxPackageActionCommands(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manager  string
		action   string
		packages []string
		want     []PackageActionCommand
		wantErr  bool
	}{
		{
			name:     "apt install refreshes metadata first",
			manager:  "apt-get",
			action:   "install",
			packages: []string{"gstreamer1.0-tools"},
			want: []PackageActionCommand{
				{Name: "apt-get", Args: []string{"update"}},
				{Name: "apt-get", Args: []string{"-y", "install", "--", "gstreamer1.0-tools"}},
			},
		},
		{
			name:    "apt upgrade refreshes metadata first",
			manager: "apt-get",
			action:  "upgrade",
			want: []PackageActionCommand{
				{Name: "apt-get", Args: []string{"update"}},
				{Name: "apt-get", Args: []string{"-y", "upgrade"}},
			},
		},
		{
			name:     "apt remove does not refresh metadata first",
			manager:  "apt-get",
			action:   "remove",
			packages: []string{"xdotool"},
			want: []PackageActionCommand{
				{Name: "apt-get", Args: []string{"-y", "remove", "--", "xdotool"}},
			},
		},
		{
			name:     "yum install stays single command",
			manager:  "yum",
			action:   "install",
			packages: []string{"xdotool"},
			want: []PackageActionCommand{
				{Name: "yum", Args: []string{"-y", "install", "xdotool"}},
			},
		},
		{
			name:     "apt rejects option-shaped package",
			manager:  "apt-get",
			action:   "install",
			packages: []string{"curl", "-o", "APT::Update::Pre-Invoke::=/bin/sh"},
			wantErr:  true,
		},
		{
			name:     "pacman rejects option-shaped package",
			manager:  "pacman",
			action:   "install",
			packages: []string{"--config", "tmp/evil"},
			wantErr:  true,
		},
		{
			name:    "unsupported manager returns error",
			manager: "pkg",
			action:  "install",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := BuildLinuxPackageActionCommands(tc.manager, tc.action, tc.packages)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("commands mismatch:\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

func TestParsePacmanPackageList(t *testing.T) {
	got, err := ParsePacmanPackageList([]byte("bash 5.2.037-1\nlinux-firmware 20250613.12fe085f-1\nmalformed\n"))
	if err != nil {
		t.Fatalf("ParsePacmanPackageList: %v", err)
	}
	want := []protocol.PackageInfo{
		{Name: "bash", Version: "5.2.037-1", Status: "installed"},
		{Name: "linux-firmware", Version: "20250613.12fe085f-1", Status: "installed"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseAPKPackageList(t *testing.T) {
	got, err := ParseAPKPackageList([]byte("busybox-1.36.1-r29\nlibcrypto3-3.3.3-r0\nfoo-bar-2.0_git20250101-r4\nmalformed\n"))
	if err != nil {
		t.Fatalf("ParseAPKPackageList: %v", err)
	}
	want := []protocol.PackageInfo{
		{Name: "busybox", Version: "1.36.1-r29", Status: "installed"},
		{Name: "libcrypto3", Version: "3.3.3-r0", Status: "installed"},
		{Name: "foo-bar", Version: "2.0_git20250101-r4", Status: "installed"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestLinuxPackageBackendListPackagesSelectsAdvertisedManagers(t *testing.T) {
	originalLookPath := LinuxPackageLookPath
	originalDpkgLister := LinuxPackageDpkgLister
	originalRPMLister := LinuxPackageRPMLister
	originalPacmanLister := LinuxPackagePacmanLister
	originalAPKLister := LinuxPackageAPKLister
	t.Cleanup(func() {
		LinuxPackageLookPath = originalLookPath
		LinuxPackageDpkgLister = originalDpkgLister
		LinuxPackageRPMLister = originalRPMLister
		LinuxPackagePacmanLister = originalPacmanLister
		LinuxPackageAPKLister = originalAPKLister
	})

	for _, manager := range []string{"dpkg-query", "rpm", "pacman", "apk"} {
		t.Run(manager, func(t *testing.T) {
			want := []protocol.PackageInfo{{Name: manager, Version: "test", Status: "installed"}}
			LinuxPackageLookPath = func(name string) (string, error) {
				if name == manager {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			}
			LinuxPackageDpkgLister = func() ([]protocol.PackageInfo, error) { return want, nil }
			LinuxPackageRPMLister = func() ([]protocol.PackageInfo, error) { return want, nil }
			LinuxPackagePacmanLister = func() ([]protocol.PackageInfo, error) { return want, nil }
			LinuxPackageAPKLister = func() ([]protocol.PackageInfo, error) { return want, nil }

			got, err := (LinuxPackageBackend{}).ListPackages()
			if err != nil {
				t.Fatalf("ListPackages: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("packages mismatch: got %#v want %#v", got, want)
			}
		})
	}
}

func TestLinuxPackageBackendListPackagesPrefersNativePacmanAndAPKOverRPM(t *testing.T) {
	originalLookPath := LinuxPackageLookPath
	originalPacmanLister := LinuxPackagePacmanLister
	originalAPKLister := LinuxPackageAPKLister
	originalRPMLister := LinuxPackageRPMLister
	t.Cleanup(func() {
		LinuxPackageLookPath = originalLookPath
		LinuxPackagePacmanLister = originalPacmanLister
		LinuxPackageAPKLister = originalAPKLister
		LinuxPackageRPMLister = originalRPMLister
	})

	for _, manager := range []string{"pacman", "apk"} {
		t.Run(manager, func(t *testing.T) {
			LinuxPackageLookPath = func(name string) (string, error) {
				if name == manager || name == "rpm" {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			}
			LinuxPackagePacmanLister = func() ([]protocol.PackageInfo, error) {
				return []protocol.PackageInfo{{Name: "pacman-native"}}, nil
			}
			LinuxPackageAPKLister = func() ([]protocol.PackageInfo, error) {
				return []protocol.PackageInfo{{Name: "apk-native"}}, nil
			}
			LinuxPackageRPMLister = func() ([]protocol.PackageInfo, error) {
				t.Fatal("secondary rpm database should not be selected")
				return nil, nil
			}

			got, err := (LinuxPackageBackend{}).ListPackages()
			if err != nil {
				t.Fatalf("ListPackages: %v", err)
			}
			wantName := manager + "-native"
			if len(got) != 1 || got[0].Name != wantName {
				t.Fatalf("packages = %#v, want native %s inventory", got, manager)
			}
		})
	}
}
