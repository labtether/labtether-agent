//go:build !windows

package system

import (
	"errors"

	"github.com/labtether/protocol"
)

func collectUserSessionsWindows() ([]protocol.UserSession, error) {
	return nil, errors.New("Windows session collection is unavailable on this platform")
}
