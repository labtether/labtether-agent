package sysconfig

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/labtether/protocol"
)

// NetworkManager handles network interface info and network actions from the hub.
type NetworkManager struct {
	mu sync.Mutex

	Backend NetworkBackend

	LastMethod          string
	LastNetplanBackup   string
	LastNMConnections   []string
	LastDarwinSnapshot  *DarwinNetworkSnapshot
	LastWindowsSnapshot *WindowsNetworkSnapshot
}

var CollectNetworkInterfaces = collectNetInterfaces

func NewNetworkManager() *NetworkManager {
	return &NetworkManager{
		Backend: NewNetworkBackendForOS(),
	}
}

// CloseAll is a no-op for NetworkManager — network requests are stateless
// aside from lightweight rollback snapshots.
func (nm *NetworkManager) CloseAll() {}

// HandleNetworkList collects network interface info and sends it to the hub.
func (nm *NetworkManager) HandleNetworkList(transport MessageSender, msg protocol.Message) {
	var req protocol.NetworkListData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("network: invalid network.list request: %v", err)
		return
	}

	ifaces, err := CollectNetworkInterfaces()

	var errMsg string
	if err != nil {
		errMsg = err.Error()
		log.Printf("network: failed to collect interfaces: %v", err)
	}

	data, marshalErr := json.Marshal(protocol.NetworkListedData{
		RequestID:  req.RequestID,
		Interfaces: ifaces,
		Error:      errMsg,
	})
	if marshalErr != nil {
		log.Printf("network: failed to marshal network.listed response: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgNetworkListed,
		ID:   req.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("network: failed to send network.listed for request %s: %v", req.RequestID, sendErr)
	}
}

// HandleNetworkAction applies or rolls back network changes using the
// platform-specific backend.
func (nm *NetworkManager) HandleNetworkAction(transport MessageSender, msg protocol.Message) {
	var req protocol.NetworkActionData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("network: invalid network.action request: %v", err)
		return
	}

	result := protocol.NetworkResultData{
		RequestID: req.RequestID,
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "apply":
		result = nm.Backend.ApplyAction(nm, req)
	case "rollback":
		result = nm.Backend.RollbackAction(nm, req)
	default:
		result.Error = "invalid action: must be apply or rollback"
	}

	nm.SendNetworkResult(transport, result)
}

func (nm *NetworkManager) SendNetworkResult(transport MessageSender, result protocol.NetworkResultData) {
	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		log.Printf("network: failed to marshal network.result: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgNetworkResult,
		ID:   result.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("network: failed to send network.result for request %s: %v", result.RequestID, sendErr)
	}
}

// collectNetInterfaces enumerates host network interfaces using the standard
// library. Per-interface counters are collected through one platform batch;
// Windows and FreeBSD take a single gopsutil snapshot per list operation.
func collectNetInterfaces() ([]protocol.NetInterface, error) {
	raw, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	interfaceNames := make([]string, 0, len(raw))
	for _, iface := range raw {
		if iface.Flags&net.FlagLoopback == 0 {
			interfaceNames = append(interfaceNames, iface.Name)
		}
	}
	statsByName, statsErr := ReadIfaceStatsBatch(interfaceNames)

	var result []protocol.NetInterface
	for _, iface := range raw {
		// Skip loopback interfaces.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}

		mac := ""
		if iface.HardwareAddr != nil {
			mac = iface.HardwareAddr.String()
		}

		addrs, addrErr := iface.Addrs()
		var ips []string
		if addrErr == nil {
			for _, addr := range addrs {
				ips = append(ips, addr.String())
			}
		}
		if ips == nil {
			ips = []string{}
		}

		stats := statsByName[iface.Name]

		result = append(result, protocol.NetInterface{
			Name:      iface.Name,
			State:     state,
			MAC:       mac,
			MTU:       iface.MTU,
			IPs:       ips,
			RXBytes:   stats.RXBytes,
			TXBytes:   stats.TXBytes,
			RXPackets: stats.RXPackets,
			TXPackets: stats.TXPackets,
		})
	}
	if statsErr != nil {
		return result, fmt.Errorf("collect per-interface network counters: %w", statsErr)
	}
	return result, nil
}
