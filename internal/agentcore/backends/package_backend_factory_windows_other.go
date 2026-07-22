//go:build !windows

package backends

func newWindowsPackageBackend() PackageBackend {
	return WindowsPackageBackend{backend: "winget"}
}
