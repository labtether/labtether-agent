package remoteaccess

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestX11WakeStopsBlockedChildWithinSharedBudget(t *testing.T) {
	original := NewX11UtilityCommand
	t.Cleanup(func() { NewX11UtilityCommand = original })
	var started []*exec.Cmd
	NewX11UtilityCommand = func(string, ...string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestX11WakeBlockedHelper$", "--", "blocked")
		started = append(started, cmd)
		return cmd, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	before := time.Now()
	wakeX11Display(ctx, ":93.1", "none")
	if elapsed := time.Since(before); elapsed > 2*time.Second {
		t.Fatalf("stuck wake held the startup path for %v", elapsed)
	}
	if len(started) != 1 || started[0].ProcessState == nil {
		t.Fatalf("wake did not reap one stuck child and stop remaining commands: %v", started)
	}
}

func TestX11WakeBlockedHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" || os.Args[len(os.Args)-1] != "blocked" {
		return
	}
	time.Sleep(5 * time.Second)
	os.Exit(0)
}
