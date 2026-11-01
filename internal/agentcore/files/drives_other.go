//go:build !windows

package files

// fixedDriveRoots returns nothing outside Windows: full mode uses the
// filesystem root, which already covers every mounted disk.
func fixedDriveRoots() []string { return nil }
