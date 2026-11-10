//go:build !windows

package backends

// windowsServiceStartTypes is only meaningful on Windows.
func windowsServiceStartTypes([]string) map[string]string { return nil }
