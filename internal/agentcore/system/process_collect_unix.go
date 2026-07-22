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

// CollectProcesses runs `ps aux --no-header` and parses the output.
// This command works on both Linux and macOS.
//
// ps aux column layout (POSIX-compatible):
//
//	USER   PID  %CPU  %MEM    VSZ   RSS  TTY  STAT  START  TIME  COMMAND
//	  0     1     2     3      4     5    6     7     8      9     10+
func CollectProcesses() ([]protocol.ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := securityruntime.CaptureCombinedOutput(
		exec.CommandContext(ctx, "ps", "aux", "--no-header"),
		securityruntime.DefaultCommandOutputLimit,
	)
	if err != nil {
		// macOS ps does not support --no-header; fall back to plain `ps aux`
		// and skip the first header line.
		out, err = securityruntime.CaptureCombinedOutput(
			exec.CommandContext(ctx, "ps", "aux"),
			securityruntime.DefaultCommandOutputLimit,
		)
		if err != nil {
			return nil, err
		}
		// Drop the header line.
		if idx := strings.IndexByte(string(out), '\n'); idx >= 0 {
			out = out[idx+1:]
		}
	}

	var processes []protocol.ProcessInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split into at most 11 fields; the last field is the full command string.
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}

		user := fields[0]
		pid, pidErr := strconv.Atoi(fields[1])
		if pidErr != nil {
			continue
		}
		cpuPct := parseProcessFloat(fields[2])
		memPct := parseProcessFloat(fields[3])
		memRSS, _ := strconv.ParseInt(fields[5], 10, 64) // RSS in KB
		// fields[10:] is the command and its arguments.
		command := strings.Join(fields[10:], " ")
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

	return processes, nil
}
