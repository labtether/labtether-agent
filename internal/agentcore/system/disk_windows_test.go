//go:build windows

package system

import (
	"os"
	"strings"
	"testing"
)

func TestCollectMountsWindowsIncludesSystemDrive(t *testing.T) {
	mounts, err := collectMountsWindows()
	if err != nil {
		t.Fatalf("collectMountsWindows: %v", err)
	}

	systemDrive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if systemDrive == "" {
		systemDrive = `C:`
	}
	wantRoot := strings.ToUpper(strings.TrimRight(systemDrive, `\/`)) + `\`
	for _, mount := range mounts {
		if !strings.EqualFold(mount.MountPoint, wantRoot) {
			continue
		}
		if mount.Device == "" || mount.FSType == "" {
			t.Fatalf("system drive has incomplete identity: %+v", mount)
		}
		if mount.Total == 0 || mount.Used > mount.Total || mount.Available > mount.Total {
			t.Fatalf("system drive has invalid capacity: %+v", mount)
		}
		if mount.UsePct < 0 || mount.UsePct > 100 {
			t.Fatalf("system drive use percent = %v", mount.UsePct)
		}
		return
	}

	t.Fatalf("system drive %q not found in mounts: %+v", wantRoot, mounts)
}
