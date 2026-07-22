//go:build windows

package backends

import "os/exec"

func newWindowsPackageBackend() PackageBackend {
	if _, err := exec.LookPath("winget"); err == nil {
		return WindowsPackageBackend{backend: "winget"}
	}
	if _, err := exec.LookPath("choco"); err == nil {
		return WindowsPackageBackend{backend: "choco"}
	}
	// Registry-backed listing remains available. If a caller bypasses the
	// advertised capabilities and requests an action, the missing WinGet command
	// fails explicitly rather than selecting an unrelated tool.
	return WindowsPackageBackend{backend: "winget"}
}
