//go:build !windows

package releasecontract

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func validateStagePermissions(info os.FileInfo) error {
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("release stage mode is %#o, want 0700", info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return errors.New("release stage must be owned by the current user")
	}
	return nil
}
