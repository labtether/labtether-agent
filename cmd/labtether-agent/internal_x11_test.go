package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/x11input"
)

// A malformed internal request must exit before banners, configuration,
// enrollment or the normal runtime can start in the helper process.
func TestInternalX11DispatchPrecedesAgentStartup(t *testing.T) {
	if os.Getenv("LABTETHER_TEST_INTERNAL_X11_MAIN") == "1" {
		os.Args = []string{os.Args[0], x11input.CommandFlag, "invalid", "50"}
		main()
		os.Exit(9)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInternalX11DispatchPrecedesAgentStartup$")
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Env = append(os.Environ(), "LABTETHER_TEST_INTERNAL_X11_MAIN=1", "LABTETHER_ALLOW_INSECURE_TRANSPORT=true", "LABTETHER_TOKEN_FILE="+filepath.Join(t.TempDir(), "unused-token"))
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil {
		t.Fatalf("internal helper did not exit promptly: %v (%s)", err, output)
	}
	if string(output) != "X11 input helper: invalid X11 key operation\n" {
		t.Fatalf("helper reached normal startup or changed failure: %q", output)
	}
}
