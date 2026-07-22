//go:build windows

package system

import (
	"os"
	"testing"
)

func TestCollectProcessesIncludesCurrentProcess(t *testing.T) {
	processes, err := CollectProcesses()
	if err != nil {
		t.Fatalf("CollectProcesses: %v", err)
	}

	currentPID := os.Getpid()
	for _, process := range processes {
		if process.PID != currentPID {
			continue
		}
		if process.Name == "" {
			t.Fatal("current process has an empty name")
		}
		if process.Command == "" {
			t.Fatal("current process has an empty command")
		}
		if process.User == "" {
			t.Fatal("current process has an empty user")
		}
		if process.MemRSS <= 0 {
			t.Fatalf("current process RSS = %d KB, want > 0", process.MemRSS)
		}
		if process.MemPct <= 0 || process.MemPct > 100 {
			t.Fatalf("current process memory percent = %v, want within (0, 100]", process.MemPct)
		}
		if process.CPUPct < 0 || process.CPUPct > 100 {
			t.Fatalf("current process CPU percent = %v, want within [0, 100]", process.CPUPct)
		}
		return
	}

	t.Fatalf("current PID %d not found in %d collected processes", currentPID, len(processes))
}
