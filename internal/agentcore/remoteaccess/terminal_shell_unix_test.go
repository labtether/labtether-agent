//go:build unix

package remoteaccess

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Risk: a shell path in the Hub's terminal request runs a planted program
// under an allowlisted name, or the agent's own shell outside PATH (its
// SHELL variable) stops working.
func TestTerminalShellFromTheHubMustBeThePATHProgram(t *testing.T) {
	dir := t.TempDir()
	bin, planted := filepath.Join(dir, "bin"), filepath.Join(dir, "plant")
	for _, folder := range []string{bin, planted} {
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, "bash"), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Mkdir(alias, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(bin, "bash"), filepath.Join(alias, "bash")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("SHELL", filepath.Join(planted, "bash"))

	_, err := newTerminalShellCommand(context.Background(), filepath.Join(planted, "bash"))
	if err == nil || !strings.Contains(err.Error(), "found in PATH") {
		t.Fatalf("Hub shell outside PATH: err %v, want a refusal", err)
	}
	cmd, err := newTerminalShellCommand(context.Background(), filepath.Join(bin, "bash"))
	if err != nil || cmd.Path != filepath.Join(bin, "bash") {
		t.Fatalf("Hub shell from PATH: %v %v", cmd, err)
	}
	// A link to the PATH program is allowed, and the PATH file is what starts.
	cmd, err = newTerminalShellCommand(context.Background(), filepath.Join(alias, "bash"))
	if err != nil || cmd.Path != filepath.Join(bin, "bash") {
		t.Fatalf("Hub shell through a link: %v %v", cmd, err)
	}
	cmd, err = newTerminalShellCommand(context.Background(), "")
	if err != nil || cmd.Path != filepath.Join(planted, "bash") {
		t.Fatalf("agent's own SHELL: %v %v", cmd, err)
	}
}
