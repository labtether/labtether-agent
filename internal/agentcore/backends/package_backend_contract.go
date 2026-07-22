package backends

import (
	"fmt"
	"runtime"

	"github.com/labtether/protocol"
)

// PackageActionResult holds the output and reboot status of a package action.
type PackageActionResult struct {
	Output         string
	RebootRequired bool
}

// UpgradablePackageInfo is the bounded agent-side representation of one
// available package update. Version is the installed/current version.
//
// This mirrors protocol.PackageInfo's additive available_version field. It is
// kept local until the separately released protocol module is tagged so this
// agent repository remains buildable against the currently published module.
type UpgradablePackageInfo struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	AvailableVersion string `json:"available_version"`
	Status           string `json:"status"`
}

// PackageBackend is the platform abstraction for querying and managing packages.
type PackageBackend interface {
	ListPackages() ([]protocol.PackageInfo, error)
	ListUpgradablePackages() ([]UpgradablePackageInfo, error)
	PerformAction(action string, packages []string) (PackageActionResult, error)
}

// NewPackageBackendForOS returns the package backend appropriate for the current OS.
func NewPackageBackendForOS() PackageBackend {
	return NewPackageBackend(runtime.GOOS)
}

// NewPackageBackend returns the package backend for the given GOOS value.
func NewPackageBackend(goos string) PackageBackend {
	switch goos {
	case "linux":
		return LinuxPackageBackend{}
	case "darwin":
		return newDarwinPackageBackend()
	case "windows":
		return newWindowsPackageBackend()
	default:
		return UnsupportedPackageBackend{OS: goos}
	}
}

// UnsupportedPackageBackend is the fallback backend for platforms without package support.
type UnsupportedPackageBackend struct {
	OS string
}

// ListPackages returns an error indicating the platform is unsupported.
func (b UnsupportedPackageBackend) ListPackages() ([]protocol.PackageInfo, error) {
	return nil, fmt.Errorf("package listing is not supported on %s", b.OS)
}

// ListUpgradablePackages returns an error indicating the platform is unsupported.
func (b UnsupportedPackageBackend) ListUpgradablePackages() ([]UpgradablePackageInfo, error) {
	return nil, fmt.Errorf("upgradable package listing is not supported on %s", b.OS)
}

// PerformAction returns an error indicating the platform is unsupported.
func (b UnsupportedPackageBackend) PerformAction(_ string, _ []string) (PackageActionResult, error) {
	return PackageActionResult{}, fmt.Errorf("package actions are not supported on %s", b.OS)
}
