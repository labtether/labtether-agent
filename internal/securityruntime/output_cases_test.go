package securityruntime

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type outputCases struct {
	Writer []struct {
		Limit     int      `json:"limit"`
		Writes    []string `json:"writes"`
		Retained  string   `json:"retained"`
		Truncated bool     `json:"truncated"`
		From      string   `json:"from"`
	} `json:"writer"`
	Capture []captureCase `json:"capture"`
}

type captureCase struct {
	Name         string  `json:"name"`
	Capture      string  `json:"capture"`
	Script       string  `json:"script"`
	Path         *string `json:"path"`
	Limit        int     `json:"limit"`
	TimeoutMS    int     `json:"timeout_ms"`
	Length       *int    `json:"length"`
	Output       *string `json:"output"`
	Stderr       *string `json:"stderr"`
	StderrLength *int    `json:"stderr_length"`
	Truncated    bool    `json:"truncated"`
	Exit         *int    `json:"exit"`
	Signal       *int    `json:"signal"`
	TimedOut     bool    `json:"timed_out"`
	MaxMS        int     `json:"max_ms"`
	Error        string  `json:"error"`
	From         string  `json:"from"`
	// The output is a process ID that must not be running afterwards.
	BackgroundPIDGone bool `json:"background_pid_gone"`
	// exec.ErrWaitDelay: a descendant still held the output.
	OutputHeld bool `json:"output_held"`
}

// Risk: output past the limit is kept, or a write is reported short and the
// command blocks on a full pipe. testdata/output_cases.json "writer".
func TestSharedWriterCases(t *testing.T) {
	var cases outputCases
	loadCases(t, "output_cases.json", &cases)
	for index, tc := range cases.Writer {
		writer := NewCappedRetainingWriter(tc.Limit)
		for _, write := range tc.Writes {
			if written, err := writer.Write([]byte(write)); err != nil || written != len(write) {
				t.Errorf("writer[%d]: Write(%q) = (%d, %v), want (%d, nil)", index, write, written, err, len(write))
			}
		}
		if got := string(writer.Bytes()); got != tc.Retained || writer.Len() != len(tc.Retained) {
			t.Errorf("writer[%d]: retained %q (len %d), want %q", index, got, writer.Len(), tc.Retained)
		}
		if writer.Truncated() != tc.Truncated {
			t.Errorf("writer[%d]: truncated %v, want %v", index, writer.Truncated(), tc.Truncated)
		}
	}
}

// Risk: a started command's output is not drained, cut or reported the way
// the agent relies on, or a timeout does not stop it.
// testdata/output_cases.json "capture"; each runs `sh -c script`.
func TestSharedCaptureCases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cases use sh")
	}
	var cases outputCases
	loadCases(t, "output_cases.json", &cases)
	applyPolicyEnv(t, nil)
	for _, tc := range cases.Capture {
		t.Run(tc.Name, func(t *testing.T) { runCaptureCase(t, tc) })
	}
}

func runCaptureCase(t *testing.T, tc captureCase) {
	if tc.Path != nil {
		t.Setenv("PATH", *tc.Path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(tc.TimeoutMS)*time.Millisecond)
	defer cancel()
	cmd, err := NewCommandContext(ctx, "sh", "-c", tc.Script)
	if err != nil {
		t.Fatalf("NewCommandContext: %v", err)
	}
	start := time.Now()
	var output []byte
	if tc.Capture == "stdout" {
		output, err = CaptureOutput(cmd, tc.Limit)
	} else {
		output, err = CaptureCombinedOutput(cmd, tc.Limit)
	}
	elapsed := time.Since(start)
	if tc.Error != "" {
		checkWant(t, "capture", err, tc.Error)
		return
	}
	var exitErr *exec.ExitError
	errors.As(err, &exitErr)
	if got := errors.Is(err, ErrCommandOutputLimit); got != tc.Truncated {
		t.Errorf("truncated %v, want %v (err %v)", got, tc.Truncated, err)
	}
	if tc.Length != nil && len(output) != *tc.Length {
		t.Errorf("output length %d, want %d", len(output), *tc.Length)
	}
	if tc.Output != nil && string(output) != *tc.Output {
		t.Errorf("output %q, want %q", output, *tc.Output)
	}
	switch {
	case tc.Exit != nil && *tc.Exit == 0 && exitErr != nil:
		t.Errorf("exit error %v, want exit 0", exitErr)
	case tc.Exit != nil && *tc.Exit != 0 && (exitErr == nil || exitErr.ExitCode() != *tc.Exit):
		t.Errorf("error %v, want exit %d", err, *tc.Exit)
	case tc.Signal != nil && (exitErr == nil || exitSignal(exitErr.ProcessState) != *tc.Signal):
		t.Errorf("error %v, want signal %d", err, *tc.Signal)
	}
	if tc.Stderr != nil && (exitErr == nil || string(exitErr.Stderr) != *tc.Stderr) {
		t.Errorf("stderr from %v, want %q", err, *tc.Stderr)
	}
	if tc.StderrLength != nil && (exitErr == nil || len(exitErr.Stderr) != *tc.StderrLength) {
		t.Errorf("stderr length from %v, want %d", err, *tc.StderrLength)
	}
	if held := errors.Is(err, exec.ErrWaitDelay); held != tc.OutputHeld {
		t.Errorf("output held %v, want %v (err %v)", held, tc.OutputHeld, err)
	}
	if tc.BackgroundPIDGone {
		pid, convErr := strconv.Atoi(strings.TrimSpace(string(output)))
		switch {
		case convErr != nil:
			t.Errorf("output %q is not a process ID", output)
		case processStillRunning(pid):
			t.Errorf("process %d still running after the call", pid)
			_ = killStrayProcess(pid)
		}
	}
	// A case that should end on its own must not reach its deadline: that
	// would mean the output was not drained.
	if timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded); timedOut != tc.TimedOut {
		t.Errorf("timed out %v, want %v", timedOut, tc.TimedOut)
	}
	if tc.MaxMS != 0 && elapsed > time.Duration(tc.MaxMS)*time.Millisecond {
		t.Errorf("took %v, want at most %d ms", elapsed, tc.MaxMS)
	}
}
