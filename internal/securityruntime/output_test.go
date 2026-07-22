package securityruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestCappedRetainingWriterDrainsAfterLimit(t *testing.T) {
	t.Parallel()

	writer := NewCappedRetainingWriter(5)
	if written, err := writer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("first Write = (%d, %v), want (6, nil)", written, err)
	}
	if written, err := writer.Write([]byte("ghijkl")); err != nil || written != 6 {
		t.Fatalf("second Write = (%d, %v), want (6, nil)", written, err)
	}
	if got := string(writer.Bytes()); got != "abcde" {
		t.Fatalf("retained bytes = %q, want %q", got, "abcde")
	}
	if writer.Len() != 5 {
		t.Fatalf("retained length = %d, want 5", writer.Len())
	}
	if !writer.Truncated() {
		t.Fatal("expected writer to report discarded bytes")
	}
}

func TestCappedRetainingWriterConcurrentWritesRemainBounded(t *testing.T) {
	t.Parallel()

	const (
		limit       = 4096
		goroutines  = 32
		bytesPerRun = 4096
	)
	writer := NewCappedRetainingWriter(limit)
	payload := bytes.Repeat([]byte("x"), bytesPerRun)

	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			written, err := writer.Write(payload)
			if err != nil || written != len(payload) {
				t.Errorf("Write = (%d, %v), want (%d, nil)", written, err, len(payload))
			}
		}()
	}
	group.Wait()

	if writer.Len() != limit {
		t.Fatalf("retained length = %d, want %d", writer.Len(), limit)
	}
	if !writer.Truncated() {
		t.Fatal("expected concurrent writer to report discarded bytes")
	}
}

func TestCaptureCombinedOutputDrainsBothStreamsAndReportsLimit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := outputHelperCommand(ctx, 2*1024*1024, 2*1024*1024, 0)

	output, err := CaptureCombinedOutput(cmd, 4096)
	if !errors.Is(err, ErrCommandOutputLimit) {
		t.Fatalf("CaptureCombinedOutput error = %v, want ErrCommandOutputLimit", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("subprocess did not drain before timeout: %v", ctx.Err())
	}
	if len(output) != 4096 {
		t.Fatalf("retained output length = %d, want 4096", len(output))
	}
}

func TestCaptureCombinedOutputPreservesProcessErrorOnLimit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := outputHelperCommand(ctx, 128*1024, 128*1024, 7)

	output, err := CaptureCombinedOutput(cmd, 1024)
	if !errors.Is(err, ErrCommandOutputLimit) {
		t.Fatalf("CaptureCombinedOutput error = %v, want ErrCommandOutputLimit", err)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("CaptureCombinedOutput error = %T %v, want exec.ExitError", err, err)
	}
	if exitErr.ExitCode() != 7 {
		t.Fatalf("exit code = %d, want 7", exitErr.ExitCode())
	}
	if len(output) != 1024 {
		t.Fatalf("retained output length = %d, want 1024", len(output))
	}
}

func TestCaptureOutputPreservesSmallOutputAndExitStderr(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := outputHelperCommand(ctx, 3, 5, 9)

	output, err := CaptureOutput(cmd, 1024)
	if string(output) != "xxx" {
		t.Fatalf("stdout = %q, want %q", output, "xxx")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("CaptureOutput error = %T %v, want exec.ExitError", err, err)
	}
	if string(exitErr.Stderr) != "yyyyy" {
		t.Fatalf("exit stderr = %q, want %q", exitErr.Stderr, "yyyyy")
	}
}

func outputHelperCommand(ctx context.Context, stdoutBytes, stderrBytes, exitCode int) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestCappedOutputHelperProcess", "--",
		strconv.Itoa(stdoutBytes), strconv.Itoa(stderrBytes), strconv.Itoa(exitCode))
	cmd.Env = append(os.Environ(), "LABTETHER_TEST_CAPPED_OUTPUT_HELPER=1")
	return cmd
}

func TestCappedOutputHelperProcess(t *testing.T) {
	if os.Getenv("LABTETHER_TEST_CAPPED_OUTPUT_HELPER") != "1" {
		return
	}
	separator := 0
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator == 0 || len(os.Args) != separator+4 {
		os.Exit(97)
	}
	stdoutBytes, stdoutErr := strconv.Atoi(os.Args[separator+1])
	stderrBytes, stderrErr := strconv.Atoi(os.Args[separator+2])
	exitCode, exitErr := strconv.Atoi(os.Args[separator+3])
	if stdoutErr != nil || stderrErr != nil || exitErr != nil {
		os.Exit(98)
	}

	writeRepeated(os.Stdout, 'x', stdoutBytes)
	writeRepeated(os.Stderr, 'y', stderrBytes)
	os.Exit(exitCode)
}

func writeRepeated(file *os.File, value byte, total int) {
	chunk := bytes.Repeat([]byte{value}, 32*1024)
	for total > 0 {
		amount := len(chunk)
		if amount > total {
			amount = total
		}
		if _, err := file.Write(chunk[:amount]); err != nil {
			os.Exit(99)
		}
		total -= amount
	}
}
