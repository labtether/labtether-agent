//go:build windows

package backends

import (
	"strings"
	"testing"
)

func TestListWindowsRegistryPackagesReturnsBoundedInstalledPrograms(t *testing.T) {
	packages, err := listWindowsRegistryPackages()
	if err != nil {
		t.Fatalf("listWindowsRegistryPackages: %v", err)
	}
	if len(packages) == 0 {
		t.Fatal("expected at least one machine-wide installed program")
	}
	if len(packages) > 100000 {
		t.Fatalf("unexpectedly large package inventory: %d", len(packages))
	}
	for i, pkg := range packages {
		if pkg.Name == "" {
			t.Fatalf("package %d has an empty name", i)
		}
		if pkg.Status != "installed" {
			t.Fatalf("package %q status=%q, want installed", pkg.Name, pkg.Status)
		}
		if i > 0 && strings.ToLower(packages[i-1].Name) > strings.ToLower(pkg.Name) {
			t.Fatalf("package inventory is not sorted near %q and %q", packages[i-1].Name, pkg.Name)
		}
	}
}
