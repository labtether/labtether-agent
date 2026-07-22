package backends

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentcore/packagepolicy"
	"github.com/labtether/protocol"
)

// PackageManager handles package inventory requests from the hub.
type PackageManager struct {
	Backend PackageBackend
}

// These additive wire fields mirror the protocol repository's next package
// contract while this repo remains pinned to the last published protocol tag.
type packageListRequestWire struct {
	RequestID string `json:"request_id"`
	Inventory string `json:"inventory,omitempty"`
}

type packageListedResponseWire struct {
	RequestID string                  `json:"request_id"`
	Inventory string                  `json:"inventory,omitempty"`
	Packages  []UpgradablePackageInfo `json:"packages"`
	Error     string                  `json:"error,omitempty"`
}

// NewPackageManager creates a PackageManager with the OS-appropriate backend.
func NewPackageManager() *PackageManager {
	return &PackageManager{
		Backend: NewPackageBackendForOS(),
	}
}

// CloseAll is a no-op for PackageManager — package requests are stateless
// and require no cleanup.
func (pm *PackageManager) CloseAll() {}

// HandlePackageList collects installed or explicitly upgradable packages and
// sends them to the hub. Upgradable responses echo the discriminator so a hub
// can reject legacy agents that ignored the additive request field.
func (pm *PackageManager) HandlePackageList(transport MessageSender, msg protocol.Message) {
	var req packageListRequestWire
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("package: invalid package.list request: %v", err)
		pm.sendPackageListedError(transport, strings.TrimSpace(msg.ID), "invalid package inventory request")
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	if req.RequestID == "" {
		req.RequestID = strings.TrimSpace(msg.ID)
	}
	if req.RequestID == "" || len(req.RequestID) > 512 {
		pm.sendPackageListedError(transport, strings.TrimSpace(msg.ID), "invalid package inventory request id")
		return
	}
	if envelopeID := strings.TrimSpace(msg.ID); envelopeID != "" && envelopeID != req.RequestID {
		pm.sendPackageListedError(transport, envelopeID, "package inventory request id mismatch")
		return
	}
	inventory := strings.ToLower(strings.TrimSpace(req.Inventory))
	if inventory != "" && inventory != PackageInventoryInstalled && inventory != PackageInventoryUpgradable {
		pm.sendPackageListed(transport, packageListedResponseWire{
			RequestID: req.RequestID,
			Inventory: inventory,
			Packages:  []UpgradablePackageInfo{},
			Error:     "invalid package inventory",
		})
		return
	}

	if inventory == PackageInventoryUpgradable {
		pkgs, err := pm.Backend.ListUpgradablePackages()
		if err == nil {
			pkgs, err = normalizeUpgradablePackages(pkgs)
		}
		var errMsg string
		if err != nil {
			errMsg = err.Error()
			log.Printf("package: failed to collect upgradable packages: %v", err)
			pkgs = []UpgradablePackageInfo{}
		}
		pm.sendPackageListed(transport, packageListedResponseWire{
			RequestID: req.RequestID,
			Inventory: PackageInventoryUpgradable,
			Packages:  pkgs,
			Error:     errMsg,
		})
		return
	}

	pkgs, err := pm.Backend.ListPackages()
	if err == nil {
		err = validateInstalledPackageInventory(pkgs)
	}

	var errMsg string
	if err != nil {
		errMsg = err.Error()
		log.Printf("package: failed to collect packages: %v", err)
		pkgs = []protocol.PackageInfo{}
	}
	if pkgs == nil {
		pkgs = []protocol.PackageInfo{}
	}

	data, marshalErr := json.Marshal(protocol.PackageListedData{
		RequestID: req.RequestID,
		Packages:  pkgs,
		Error:     errMsg,
	})
	if marshalErr != nil {
		log.Printf("package: failed to marshal package.listed response: %v", marshalErr)
		return
	}
	if len(data) > MaxPackageInventoryPayloadBytes {
		pm.sendPackageListedError(
			transport,
			req.RequestID,
			fmt.Sprintf("package inventory response exceeds %d bytes", MaxPackageInventoryPayloadBytes),
		)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgPackageListed,
		ID:   req.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("package: failed to send package.listed for request %s: %v", req.RequestID, sendErr)
	}
}

func (pm *PackageManager) sendPackageListedError(transport MessageSender, requestID, errMsg string) {
	pm.sendPackageListed(transport, packageListedResponseWire{
		RequestID: strings.TrimSpace(requestID),
		Packages:  []UpgradablePackageInfo{},
		Error:     errMsg,
	})
}

func (pm *PackageManager) sendPackageListed(transport MessageSender, response packageListedResponseWire) {
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("package: failed to marshal package.listed response: %v", err)
		return
	}
	if len(data) > MaxPackageInventoryPayloadBytes {
		response.Packages = []UpgradablePackageInfo{}
		response.Error = fmt.Sprintf("package inventory response exceeds %d bytes", MaxPackageInventoryPayloadBytes)
		data, err = json.Marshal(response)
		if err != nil {
			log.Printf("package: failed to marshal bounded package.listed response: %v", err)
			return
		}
	}
	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgPackageListed,
		ID:   response.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("package: failed to send package.listed for request %s: %v", response.RequestID, sendErr)
	}
}

// HandlePackageAction performs a package-manager operation and returns result details.
func (pm *PackageManager) HandlePackageAction(transport MessageSender, msg protocol.Message) {
	var req protocol.PackageActionData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("package: invalid package.action request: %v", err)
		pm.sendPackageResult(transport, strings.TrimSpace(msg.ID), false, "", "invalid package action request", false)
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	if req.RequestID == "" {
		req.RequestID = strings.TrimSpace(msg.ID)
	}
	if req.RequestID == "" || len(req.RequestID) > 512 {
		pm.sendPackageResult(transport, strings.TrimSpace(msg.ID), false, "", "invalid package action request id", false)
		return
	}
	if envelopeID := strings.TrimSpace(msg.ID); envelopeID != "" && envelopeID != req.RequestID {
		pm.sendPackageResult(transport, envelopeID, false, "", "package action request id mismatch", false)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "update" {
		action = "upgrade"
	}
	if action != "install" && action != "remove" && action != "upgrade" {
		pm.sendPackageResult(transport, req.RequestID, false, "", "invalid package action", false)
		return
	}

	packages, err := packagepolicy.NormalizeAndValidate(req.Packages)
	if err != nil {
		pm.sendPackageResult(transport, req.RequestID, false, "", err.Error(), false)
		return
	}
	if (action == "install" || action == "remove") && len(packages) == 0 {
		pm.sendPackageResult(transport, req.RequestID, false, "", "at least one package is required", false)
		return
	}

	result, err := pm.Backend.PerformAction(action, packages)
	if err != nil {
		pm.sendPackageResult(transport, req.RequestID, false, result.Output, err.Error(), result.RebootRequired)
		return
	}

	pm.sendPackageResult(transport, req.RequestID, true, result.Output, "", result.RebootRequired)
}

func (pm *PackageManager) sendPackageResult(
	transport MessageSender,
	requestID string,
	ok bool,
	output,
	errMsg string,
	rebootRequired bool,
) {
	data, marshalErr := json.Marshal(protocol.PackageResultData{
		RequestID:      requestID,
		OK:             ok,
		Output:         output,
		Error:          errMsg,
		RebootRequired: rebootRequired,
	})
	if marshalErr != nil {
		log.Printf("package: failed to marshal package.result: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgPackageResult,
		ID:   requestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("package: failed to send package.result for request %s: %v", requestID, sendErr)
	}
}
