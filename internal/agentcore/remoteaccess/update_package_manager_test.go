package remoteaccess

import (
	"errors"
	"reflect"
	"testing"
)

func TestBuildUpdatePackageCommand(t *testing.T) {
	tests := []struct {
		name     string
		manager  string
		packages []string
		want     UpdatePackageCommand
	}{
		{name: "apt all", manager: "apt-get", want: UpdatePackageCommand{Name: "apt-get", Args: []string{"-y", "upgrade"}}},
		{name: "apt packages", manager: "apt-get", packages: []string{"curl"}, want: UpdatePackageCommand{Name: "apt-get", Args: []string{"-y", "install", "--", "curl"}}},
		{name: "dnf all", manager: "dnf", want: UpdatePackageCommand{Name: "dnf", Args: []string{"-y", "upgrade"}}},
		{name: "yum packages", manager: "yum", packages: []string{"curl"}, want: UpdatePackageCommand{Name: "yum", Args: []string{"-y", "install", "curl"}}},
		{name: "zypper all", manager: "zypper", want: UpdatePackageCommand{Name: "zypper", Args: []string{"--non-interactive", "update"}}},
		{name: "zypper packages", manager: "zypper", packages: []string{"curl"}, want: UpdatePackageCommand{Name: "zypper", Args: []string{"--non-interactive", "install", "curl"}}},
		{name: "pacman all", manager: "pacman", want: UpdatePackageCommand{Name: "pacman", Args: []string{"--noconfirm", "-Syu"}}},
		{name: "pacman packages", manager: "pacman", packages: []string{"curl"}, want: UpdatePackageCommand{Name: "pacman", Args: []string{"--noconfirm", "-S", "--", "curl"}}},
		{name: "apk all", manager: "apk", want: UpdatePackageCommand{Name: "apk", Args: []string{"upgrade"}}},
		{name: "apk packages", manager: "apk", packages: []string{"curl"}, want: UpdatePackageCommand{Name: "apk", Args: []string{"add", "--upgrade", "curl"}}},
		{name: "brew all", manager: "brew", want: UpdatePackageCommand{Name: "brew", Args: []string{"upgrade"}}},
		{name: "brew packages", manager: "brew", packages: []string{"curl"}, want: UpdatePackageCommand{Name: "brew", Args: []string{"install", "--", "curl"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildUpdatePackageCommand(tc.manager, tc.packages)
			if err != nil {
				t.Fatalf("BuildUpdatePackageCommand: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("command mismatch:\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

func TestResolveUpdatePackageCommandDetectsEverySupportedManager(t *testing.T) {
	for _, manager := range []string{"apt-get", "dnf", "yum", "zypper", "pacman", "apk", "brew"} {
		t.Run(manager, func(t *testing.T) {
			got, err := ResolveUpdatePackageCommand(nil, func(candidate string) (string, error) {
				if candidate == manager {
					return "/usr/bin/" + candidate, nil
				}
				return "", errors.New("not found")
			})
			if err != nil {
				t.Fatalf("ResolveUpdatePackageCommand: %v", err)
			}
			if got.Name != manager {
				t.Fatalf("manager = %q, want %q", got.Name, manager)
			}
		})
	}
}

func TestResolveUpdatePackageCommandPrefersBackendOrder(t *testing.T) {
	got, err := ResolveUpdatePackageCommand(nil, func(candidate string) (string, error) {
		return "/usr/bin/" + candidate, nil
	})
	if err != nil {
		t.Fatalf("ResolveUpdatePackageCommand: %v", err)
	}
	if got.Name != "apt-get" {
		t.Fatalf("manager = %q, want apt-get", got.Name)
	}
}

func TestBuildAndResolveUpdatePackageCommandRejectUnsupported(t *testing.T) {
	if _, err := BuildUpdatePackageCommand("pkg", nil); err == nil {
		t.Fatal("expected unsupported manager error")
	}
	if _, err := ResolveUpdatePackageCommand(nil, func(string) (string, error) {
		return "", errors.New("not found")
	}); err == nil {
		t.Fatal("expected missing manager error")
	}
}

func TestBuildUpdatePackageCommandRejectsOptionInjection(t *testing.T) {
	tests := []struct {
		manager  string
		packages []string
	}{
		{manager: "apt-get", packages: []string{"curl", "-o", "APT::Update::Pre-Invoke::=/bin/sh"}},
		{manager: "pacman", packages: []string{"--config", "tmp/evil"}},
		{manager: "brew", packages: []string{"--formula", "curl"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.manager, func(t *testing.T) {
			if _, err := BuildUpdatePackageCommand(test.manager, test.packages); err == nil {
				t.Fatalf("expected %s option injection to be rejected", test.manager)
			}
		})
	}
}
