package backends

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseBrewInstalledPackages(t *testing.T) {
	raw := []byte(`{
		"formulae": [
			{
				"name": "wget",
				"full_name": "wget",
				"installed": [{"version": "1.24.5"}],
				"versions": {"stable": "1.24.5"}
			},
			{
				"name": "jq",
				"full_name": "jq",
				"installed": [],
				"versions": {"stable": "1.7.1"}
			}
		],
		"casks": [
			{
				"token": "iterm2",
				"version": "3.5.0",
				"installed": ["3.5.0"]
			}
		]
	}`)

	packages, err := ParseBrewInstalledPackages(raw)
	if err != nil {
		t.Fatalf("ParseBrewInstalledPackages returned error: %v", err)
	}

	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.Name)
		if pkg.Status != "installed" {
			t.Fatalf("expected installed status, got %q for %s", pkg.Status, pkg.Name)
		}
	}

	wantNames := []string{"iterm2", "jq", "wget"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("package names=%v, want %v", names, wantNames)
	}
}

func TestParseBrewInstalledPackagesCaskInstalledAsString(t *testing.T) {
	raw := []byte(`{
		"formulae": [],
		"casks": [
			{
				"token": "visual-studio-code",
				"version": "1.98.0",
				"installed": "1.98.0"
			}
		]
	}`)

	packages, err := ParseBrewInstalledPackages(raw)
	if err != nil {
		t.Fatalf("ParseBrewInstalledPackages returned error: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "visual-studio-code" {
		t.Fatalf("package name=%q, want visual-studio-code", packages[0].Name)
	}
	if packages[0].Version != "1.98.0" {
		t.Fatalf("package version=%q, want 1.98.0", packages[0].Version)
	}
}

func TestParseBrewInstalledPackagesInvalidJSON(t *testing.T) {
	_, err := ParseBrewInstalledPackages([]byte(`not-json`))
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestParseBrewInstalledPackagesIgnoresAdvisoryPrefix(t *testing.T) {
	raw := []byte("â advisory text before json\n" + `{
		"formulae": [
			{
				"name": "wget",
				"full_name": "wget",
				"installed": [{"version": "1.24.5"}],
				"versions": {"stable": "1.24.5"}
			}
		],
		"casks": []
	}` + "\ntrailing text")

	packages, err := ParseBrewInstalledPackages(raw)
	if err != nil {
		t.Fatalf("ParseBrewInstalledPackages returned error: %v", err)
	}
	if len(packages) != 1 || packages[0].Name != "wget" {
		t.Fatalf("packages=%#v, want wget", packages)
	}
}

func TestParseBrewUpgradablePackages(t *testing.T) {
	raw := []byte(`{
		"formulae": [{"name":"wget","installed_versions":["1.24.0"],"current_version":"1.25.0"}],
		"casks": [{"name":"iterm2","installed_versions":["3.5.0"],"current_version":"3.6.0"}]
	}`)
	got, err := ParseBrewUpgradablePackages(raw)
	if err != nil {
		t.Fatalf("ParseBrewUpgradablePackages: %v", err)
	}
	want := []UpgradablePackageInfo{
		{Name: "wget", Version: "1.24.0", AvailableVersion: "1.25.0"},
		{Name: "iterm2", Version: "3.5.0", AvailableVersion: "3.6.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages = %#v, want %#v", got, want)
	}
}

func TestResolveDarwinBrewPathUsesLookPathResult(t *testing.T) {
	originalLookPath := DarwinPackageLookPath
	t.Cleanup(func() { DarwinPackageLookPath = originalLookPath })

	tempDir := t.TempDir()
	brew := filepath.Join(tempDir, "brew")
	if err := os.WriteFile(brew, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	DarwinPackageLookPath = func(string) (string, error) { return brew, nil }

	got, err := ResolveDarwinBrewPath()
	if err != nil {
		t.Fatalf("ResolveDarwinBrewPath() error = %v", err)
	}
	if got != brew {
		t.Fatalf("ResolveDarwinBrewPath() = %q, want %q", got, brew)
	}
}

func TestDarwinUpgradableInventoryTimeoutAndMalformedOutput(t *testing.T) {
	originalLookPath := DarwinPackageLookPath
	originalRun := RunDarwinPackageInventoryCommand
	t.Cleanup(func() {
		DarwinPackageLookPath = originalLookPath
		RunDarwinPackageInventoryCommand = originalRun
	})
	DarwinPackageLookPath = func(string) (string, error) { return "/opt/homebrew/bin/brew", nil }

	t.Run("timeout", func(t *testing.T) {
		RunDarwinPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
			return nil, context.DeadlineExceeded
		}
		_, err := (DarwinPackageBackend{}).ListUpgradablePackages()
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("timeout error = %v", err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		RunDarwinPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
			return []byte(`{"formulae":[{"name":"wget","installed_versions":[],"current_version":"1.25.0"}]}`), nil
		}
		_, err := (DarwinPackageBackend{}).ListUpgradablePackages()
		if err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("malformed error = %v", err)
		}
	})

	t.Run("look path", func(t *testing.T) {
		DarwinPackageLookPath = func(string) (string, error) { return "", errors.New("missing") }
		RunDarwinPackageInventoryCommand = func(context.Context, string, ...string) ([]byte, error) {
			return []byte(`{"formulae":[],"casks":[]}`), nil
		}
		_, err := (DarwinPackageBackend{}).ListUpgradablePackages()
		if err != nil && !strings.Contains(err.Error(), "not available") {
			t.Fatalf("look path error = %v", err)
		}
	})
}

func TestBuildDarwinPackageActionArgs(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		packages []string
		want     []string
		wantErr  bool
	}{
		{
			name:     "install",
			action:   "install",
			packages: []string{"wget", "jq"},
			want:     []string{"install", "--", "wget", "jq"},
		},
		{
			name:     "remove",
			action:   "remove",
			packages: []string{"wget"},
			want:     []string{"uninstall", "--", "wget"},
		},
		{
			name:   "upgrade-all",
			action: "upgrade",
			want:   []string{"upgrade"},
		},
		{
			name:     "upgrade-specific",
			action:   "upgrade",
			packages: []string{"wget"},
			want:     []string{"upgrade", "--", "wget"},
		},
		{
			name:     "rejects brew option injection",
			action:   "install",
			packages: []string{"--formula", "wget"},
			wantErr:  true,
		},
		{
			name:    "invalid",
			action:  "noop",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildDarwinPackageActionArgs(tc.action, tc.packages)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("args=%v, want %v", got, tc.want)
			}
		})
	}
}
