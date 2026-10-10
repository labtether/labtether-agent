//go:build !windows

package system

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// CollectProcesses requests explicit columns so ps variants cannot silently
// change the field positions. BusyBox lacks CPU and memory percentage columns.
func CollectProcesses() ([]protocol.ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return collectProcessesWithPS(func(args ...string) ([]byte, error) {
		return securityruntime.CaptureCombinedOutput(
			exec.CommandContext(ctx, "ps", args...),
			securityruntime.DefaultCommandOutputLimit,
		)
	})
}

func collectProcessesWithPS(run func(...string) ([]byte, error)) ([]protocol.ProcessInfo, error) {
	out, err := run("-axo", "user=,pid=,%cpu=,%mem=,rss=,command=")
	if err == nil {
		return parseProcessRows(out, true), nil
	}
	out, err = run("-o", "user=,pid=,rss=,args=")
	if err != nil {
		return nil, err
	}
	return parseProcessRows(out, false), nil
}

func parseProcessRows(out []byte, withPercentages bool) []protocol.ProcessInfo {
	var processes []protocol.ProcessInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		minimumFields := 4
		if withPercentages {
			minimumFields = 6
		}
		if len(fields) < minimumFields {
			continue
		}
		user := fields[0]
		pid, pidErr := strconv.Atoi(fields[1])
		if pidErr != nil {
			continue
		}
		var cpuPct, memPct float64
		rssIndex, commandIndex := 2, 3
		if withPercentages {
			cpuPct = parseProcessFloat(fields[2])
			memPct = parseProcessFloat(fields[3])
			rssIndex, commandIndex = 4, 5
		}
		memRSS := parsePSRSSKB(fields[rssIndex])
		command := strings.Join(fields[commandIndex:], " ")
		// Derive a short name from the command path (last path component).
		name := command
		if parts := strings.Fields(command); len(parts) > 0 {
			exe := parts[0]
			if idx := strings.LastIndexByte(exe, '/'); idx >= 0 {
				exe = exe[idx+1:]
			}
			name = exe
		}

		processes = append(processes, protocol.ProcessInfo{
			PID:     pid,
			Name:    name,
			User:    user,
			CPUPct:  cpuPct,
			MemPct:  memPct,
			MemRSS:  memRSS,
			Command: command,
		})
	}
	return processes
}

func parsePSRSSKB(raw string) int64 {
	if size, err := strconv.ParseInt(raw, 10, 64); err == nil && size >= 0 {
		return size
	}
	if len(raw) < 2 {
		return 0
	}
	factor := float64(0)
	switch raw[len(raw)-1] {
	case 'k', 'K':
		factor = 1
	case 'm', 'M':
		factor = 1024
	case 'g', 'G':
		factor = 1024 * 1024
	}
	size, err := strconv.ParseFloat(raw[:len(raw)-1], 64)
	if err != nil || size < 0 || factor == 0 || size*factor > 1<<50 {
		return 0
	}
	return int64(size*factor + 0.5)
}
