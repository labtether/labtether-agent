package agentcore

import (
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/labtether-agent/internal/agentcore/system"
	"github.com/labtether/protocol"
)

// dispatchNodeMessage owns host inventory and management operations. Authorization
// remains in receiveLoop, before any domain dispatcher is called.
func dispatchNodeMessage(msg protocol.Message, transport *wsTransport, dispatch func(string, func()),
	processMgr *system.ProcessManager, serviceMgr *backends.ServiceManager, journalMgr *backends.JournalManager,
	diskMgr *system.DiskManager, networkMgr *networkManager, packageMgr *backends.PackageManager,
	cronMgr *backends.CronManager, usersMgr *system.UsersManager) bool {
	switch msg.Type {
	case protocol.MsgProcessList:
		if processMgr != nil {
			dispatch("process-list", func() {
				processMgr.HandleProcessList(transport, msg)
			})
		}
	case protocol.MsgProcessKill:
		if processMgr != nil {
			dispatch("process-kill", func() {
				processMgr.HandleProcessKill(transport, msg)
			})
		}
	case protocol.MsgServiceList:
		if serviceMgr != nil {
			dispatch("service-list", func() {
				serviceMgr.HandleServiceList(transport, msg)
			})
		}
	case protocol.MsgServiceAction:
		if serviceMgr != nil {
			dispatch("service-action", func() {
				serviceMgr.HandleServiceAction(transport, msg)
			})
		}
	case protocol.MsgJournalQuery:
		if journalMgr != nil {
			dispatch("journal-query", func() {
				journalMgr.HandleJournalQuery(transport, msg)
			})
		}
	case protocol.MsgDiskList:
		if diskMgr != nil {
			dispatch("disk-list", func() {
				diskMgr.HandleDiskList(transport, msg)
			})
		}
	case protocol.MsgNetworkList:
		if networkMgr != nil {
			dispatch("network-list", func() {
				networkMgr.HandleNetworkList(transport, msg)
			})
		}
	case protocol.MsgNetworkAction:
		if networkMgr != nil {
			dispatch("network-action", func() {
				networkMgr.HandleNetworkAction(transport, msg)
			})
		}
	case protocol.MsgPackageList:
		if packageMgr != nil {
			dispatch("package-list", func() {
				packageMgr.HandlePackageList(transport, msg)
			})
		}
	case protocol.MsgPackageAction:
		if packageMgr != nil {
			dispatch("package-action", func() {
				packageMgr.HandlePackageAction(transport, msg)
			})
		}
	case protocol.MsgCronList:
		if cronMgr != nil {
			dispatch("cron-list", func() {
				cronMgr.HandleCronList(transport, msg)
			})
		}
	case protocol.MsgUsersList:
		if usersMgr != nil {
			dispatch("users-list", func() {
				usersMgr.HandleUsersList(transport, msg)
			})
		}
	default:
		return false
	}
	return true
}
