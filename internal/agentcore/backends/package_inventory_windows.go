//go:build windows

package backends

import (
	"fmt"
	"sort"
	"strings"

	"github.com/labtether/protocol"
	"golang.org/x/sys/windows/registry"
)

var windowsUninstallRegistryRoots = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// listWindowsRegistryPackages reads machine-wide installed-program metadata.
// Both the native and WOW6432 uninstall views are included, then duplicate
// display-name/version pairs are collapsed deterministically.
func listWindowsRegistryPackages() ([]protocol.PackageInfo, error) {
	packages := make([]protocol.PackageInfo, 0, 256)
	seen := make(map[string]struct{}, 256)
	var rootErrors []string
	successfulRoots := 0

	for _, rootPath := range windowsUninstallRegistryRoots {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			rootErrors = append(rootErrors, fmt.Sprintf("%s: %v", rootPath, err))
			continue
		}
		subkeyNames, err := root.ReadSubKeyNames(-1)
		root.Close()
		if err != nil {
			rootErrors = append(rootErrors, fmt.Sprintf("%s: %v", rootPath, err))
			continue
		}
		successfulRoots++

		for _, subkeyName := range subkeyNames {
			subkey, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath+`\`+subkeyName, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, nameErr := subkey.GetStringValue("DisplayName")
			version, _, _ := subkey.GetStringValue("DisplayVersion")
			systemComponent, _, componentErr := subkey.GetIntegerValue("SystemComponent")
			subkey.Close()

			name = strings.TrimSpace(name)
			version = strings.TrimSpace(version)
			if nameErr != nil || name == "" || (componentErr == nil && systemComponent == 1) {
				continue
			}
			key := strings.ToLower(name) + "\x00" + strings.ToLower(version)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			packages = append(packages, protocol.PackageInfo{
				Name:    name,
				Version: version,
				Status:  "installed",
			})
		}
	}

	if successfulRoots == 0 {
		return nil, fmt.Errorf("Windows package registry inventory failed: %s", strings.Join(rootErrors, "; "))
	}
	sort.Slice(packages, func(i, j int) bool {
		leftName, rightName := strings.ToLower(packages[i].Name), strings.ToLower(packages[j].Name)
		if leftName == rightName {
			return strings.ToLower(packages[i].Version) < strings.ToLower(packages[j].Version)
		}
		return leftName < rightName
	})
	return packages, nil
}
