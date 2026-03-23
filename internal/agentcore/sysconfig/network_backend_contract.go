package sysconfig

import (
	"fmt"
	"runtime"

	"github.com/labtether/protocol"
)

type NetworkBackend interface {
	ApplyAction(nm *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData
	RollbackAction(nm *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData
}

func NewNetworkBackendForOS() NetworkBackend {
	return NewNetworkBackend(runtime.GOOS)
}

func NewNetworkBackend(goos string) NetworkBackend {
	switch goos {
	case "linux":
		return LinuxNetworkBackend{}
	case "darwin":
		return DarwinNetworkBackend{}
	case "windows":
		return WindowsNetworkBackend{}
	default:
		return UnsupportedNetworkBackend{OS: goos}
	}
}

type UnsupportedNetworkBackend struct {
	OS string
}

func (b UnsupportedNetworkBackend) ApplyAction(_ *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData {
	return protocol.NetworkResultData{
		RequestID: req.RequestID,
		Error:     fmt.Sprintf("network actions are not supported on %s", b.OS),
	}
}

func (b UnsupportedNetworkBackend) RollbackAction(_ *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData {
	return protocol.NetworkResultData{
		RequestID: req.RequestID,
		Error:     fmt.Sprintf("network rollback is not supported on %s", b.OS),
	}
}
