package sysconfig

import "github.com/labtether/protocol"

type LinuxNetworkBackend struct{}

func (LinuxNetworkBackend) ApplyAction(nm *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData {
	return nm.ApplyActionLinux(req)
}

func (LinuxNetworkBackend) RollbackAction(nm *NetworkManager, req protocol.NetworkActionData) protocol.NetworkResultData {
	return nm.RollbackActionLinux(req)
}
