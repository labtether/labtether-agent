package sysconfig

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

func clipboardHelperCommand(t *testing.T, mode, acknowledgement string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestClipboardCommandHelperProcess$")
	cmd.Env = append(os.Environ(), "LABTETHER_CLIPBOARD_HELPER="+mode,
		"LABTETHER_CLIPBOARD_ACK="+acknowledgement)
	return cmd
}

func TestClipboardCommandKillsBlockedInputConsumer(t *testing.T) {
	cmd := clipboardHelperCommand(t, "blocked", "")
	cmd.Stdin = strings.NewReader(strings.Repeat("x", 1024*1024))
	started := time.Now()
	err := runClipboardCommand(cmd, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline", err)
	}
	if time.Since(started) > 3*time.Second || cmd.ProcessState == nil {
		t.Fatal("blocked child was not reaped within the command bound")
	}
}

func TestClipboardCommandBoundsInheritedOutputAndPreservesWriteOwner(t *testing.T) {
	for _, capture := range []bool{true, false} {
		name := "write_owner"
		if capture {
			name = "inherited_output"
		}
		t.Run(name, func(t *testing.T) {
			acknowledgement := filepath.Join(t.TempDir(), "owner-response")
			input, release, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer release.Close()
			cmd := clipboardHelperCommand(t, "owner", acknowledgement)
			cmd.Stdin = input
			started := time.Now()
			if capture {
				var output []byte
				output, err = captureClipboardOutput(cmd, 2*time.Second)
				if !errors.Is(err, exec.ErrWaitDelay) || string(output) != "final bytes\r\n\n" {
					t.Fatalf("capture = %q, %v; want exact output and bounded pipe drain", output, err)
				}
			} else if err = runClipboardCommand(cmd, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			if time.Since(started) > 3*time.Second {
				t.Fatal("inherited handle kept the command running")
			}
			// Ask the child to act only after the helper returned. An unconditional
			// process-group kill would destroy the real X11 selection owner here.
			if _, err := release.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				if result, err := os.ReadFile(acknowledgement); err == nil && string(result) == "x" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("successful command killed its background clipboard owner")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestClipboardCommandPreservesOutputLimitError(t *testing.T) {
	cmd := clipboardHelperCommand(t, "overflow", "")
	output, err := captureClipboardOutput(cmd, 2*time.Second)
	if !errors.Is(err, securityruntime.ErrCommandOutputLimit) || len(output) != securityruntime.DefaultCommandOutputLimit {
		t.Fatalf("output length = %d, error = %v; want capped output and typed overflow", len(output), err)
	}
}

// Runs only in isolated test subprocesses, never a real platform clipboard.
func TestClipboardCommandHelperProcess(t *testing.T) {
	mode := os.Getenv("LABTETHER_CLIPBOARD_HELPER")
	if mode == "" {
		return
	}
	// A failed assertion in the parent must not leave a fixture child behind.
	time.AfterFunc(5*time.Second, func() { os.Exit(3) })
	switch mode {
	case "blocked":
		time.Sleep(30 * time.Second)
	case "owner":
		_, _ = os.Stdout.WriteString("final bytes\r\n\n")
		child := clipboardHelperCommand(t, "descendant", os.Getenv("LABTETHER_CLIPBOARD_ACK"))
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_ = child.Process.Release()
	case "descendant":
		value := make([]byte, 1)
		if _, err := io.ReadFull(os.Stdin, value); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("LABTETHER_CLIPBOARD_ACK"), value, 0600); err != nil {
			os.Exit(2)
		}
	case "overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), securityruntime.DefaultCommandOutputLimit+1))
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
