package remoteaccess

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestPipeTerminalReportsExitBeforeOutputDrain(t *testing.T) {
	const finalOutput = "final stdout and stderr bytes\n"
	exitErr := errors.New("fixture shell exit")
	input, output, processDone, err := startTerminalPipeBridge(
		func(_ io.Reader, writer io.Writer) error {
			// Model output already written when the shell exits. No real process
			// runs, and the consumer deliberately has not drained the pipe yet.
			_, err := io.WriteString(writer, finalOutput)
			return err
		},
		func() error { return exitErr },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()

	select {
	case err := <-processDone:
		if !errors.Is(err, exitErr) {
			t.Fatalf("exit error = %v, want %v", err, exitErr)
		}
	case <-time.After(time.Second):
		t.Fatal("shell exit waited for output consumption; the drain timer cannot start")
	}

	got, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != finalOutput {
		t.Fatalf("final output = %q, want %q", got, finalOutput)
	}
}
