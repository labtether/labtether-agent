//go:build windows

package releasecontract

import "os"

func validateStagePermissions(_ os.FileInfo) error {
	return nil
}
