package system

import (
	"encoding/json"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/labtether/protocol"
)

// MessageSender abstracts the agent-to-hub send capability so this package
// does not depend on the concrete wsTransport type in the parent agentcore package.
type MessageSender interface {
	Send(msg protocol.Message) error
}

// ProcessManager handles process list requests from the hub.
// It carries no persistent state; the struct exists for consistency
// with the other manager types.
type ProcessManager struct{}

var (
	CollectProcessesFn = CollectProcesses
	KillProcessFn      = KillProcess
)

// NewProcessManager creates a new ProcessManager.
func NewProcessManager() *ProcessManager {
	return &ProcessManager{}
}

// CloseAll is a no-op for ProcessManager -- process list requests are
// stateless and require no cleanup.
func (pm *ProcessManager) CloseAll() {}

// HandleProcessKill sends a signal to a process identified by PID.
func (pm *ProcessManager) HandleProcessKill(transport MessageSender, msg protocol.Message) {
	var req protocol.ProcessKillData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("process: invalid process.kill request: %v", err)
		return
	}

	result := protocol.ProcessKillResultData{PID: req.PID}

	if req.PID <= 1 {
		result.Error = "refusing to signal PID <= 1"
		sendProcessKillResult(transport, msg.ID, result)
		return
	}

	if err := KillProcessFn(req.PID, req.Signal); err != nil {
		result.Error = err.Error()
	} else {
		result.Success = true
	}

	sendProcessKillResult(transport, msg.ID, result)
}

// sendProcessKillResult marshals and transmits a ProcessKillResultData to the hub.
func sendProcessKillResult(transport MessageSender, requestID string, result protocol.ProcessKillResultData) {
	data, err := json.Marshal(result)
	if err != nil {
		log.Printf("process: failed to marshal process.kill_result: %v", err)
		return
	}
	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgProcessKillResult,
		ID:   requestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("process: failed to send process.kill_result for PID %d: %v", result.PID, sendErr)
	}
}

// HandleProcessList collects the running process list and sends it to the hub.
func (pm *ProcessManager) HandleProcessList(transport MessageSender, msg protocol.Message) {
	var req protocol.ProcessListData
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("process: invalid process.list request: %v", err)
		return
	}

	// Apply defaults.
	sortBy := req.SortBy
	if sortBy == "" {
		sortBy = "cpu"
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 25
	}

	processes, err := CollectProcessesFn()

	var errMsg string
	if err != nil {
		errMsg = err.Error()
		log.Printf("process: failed to collect processes: %v", err)
	}

	// Sort by the requested field.
	switch sortBy {
	case "memory":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].MemPct > processes[j].MemPct
		})
	default: // "cpu"
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPUPct > processes[j].CPUPct
		})
	}

	// Truncate to limit.
	if len(processes) > limit {
		processes = processes[:limit]
	}

	data, marshalErr := json.Marshal(protocol.ProcessListedData{
		RequestID: req.RequestID,
		Processes: processes,
		Error:     errMsg,
	})
	if marshalErr != nil {
		log.Printf("process: failed to marshal process.listed response: %v", marshalErr)
		return
	}

	if sendErr := transport.Send(protocol.Message{
		Type: protocol.MsgProcessListed,
		ID:   req.RequestID,
		Data: data,
	}); sendErr != nil {
		log.Printf("process: failed to send process.listed for request %s: %v", req.RequestID, sendErr)
	}
}

func parseProcessFloat(raw string) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}
