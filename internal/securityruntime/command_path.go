package securityruntime

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// The exec allowlist names programs, not files. A program given with a
// folder must therefore be the same file that a lookup of its bare name in
// the agent's PATH finds; otherwise anyone who can put a file on the device
// could run it under an allowlisted name ("/tmp/x/bash"). The command then
// starts the file PATH gives, not the path as given, so a link swapped after
// the check cannot change what runs.
//
// Code that picks a full path itself (a constant, or an install location it
// found) uses NewAgentPathCommandContext instead.

// execNameHasFolder reports whether name is more than a bare program name.
// A backslash counts on every system: the name rules already read it as a
// folder separator, and a Windows path must not pass as a bare name.
func execNameHasFolder(name string) bool {
	if strings.ContainsAny(name, `/\`) {
		return true
	}
	return runtime.GOOS == "windows" && filepath.VolumeName(name) != ""
}

func errExecNotFullPath(name string) error {
	return fmt.Errorf("command %q must be a program name or a full path", name)
}

// resolveExecProgram applies the exec rules to name and returns the program
// to start: name itself for a bare name, or the file PATH finds for a full
// path that is that same file.
func resolveExecProgram(name string) (string, error) {
	normalized, checkPath, err := validateExecName(name)
	if err != nil {
		return "", err
	}
	if !checkPath || !execNameHasFolder(name) {
		return name, nil
	}
	if !filepath.IsAbs(name) {
		return "", errExecNotFullPath(name)
	}
	found, err := exec.LookPath(filepath.Base(name))
	if err == nil {
		var given string
		if given, err = exec.LookPath(name); err == nil && sameExecutable(given, found) {
			return found, nil
		}
	}
	return "", fmt.Errorf("command %q is not the %q found in PATH", name, normalized)
}

// sameExecutable reports whether two paths name one file once every link is
// resolved. Windows paths compare without regard to case.
func sameExecutable(a, b string) bool {
	resolvedA, errA := filepath.EvalSymlinks(a)
	resolvedB, errB := filepath.EvalSymlinks(b)
	if errA != nil || errB != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(resolvedA, resolvedB)
	}
	return resolvedA == resolvedB
}

// NewAgentPathCommandContext starts a program whose full path the agent's own
// code chose: a constant such as /usr/sbin/networksetup, or a file the agent
// found itself (Homebrew's install folders, the agent's SHELL variable). The
// name must pass the exec rules, as for NewCommandContext, but the path need
// not be the one PATH finds. Never pass a value from a Hub message here; use
// NewCommandContext, which refuses a path that is not the PATH program.
func NewAgentPathCommandContext(ctx context.Context, path string, args ...string) (*exec.Cmd, error) {
	if _, _, err := validateExecName(path); err != nil {
		return nil, err
	}
	if execNameHasFolder(path) && !filepath.IsAbs(path) {
		return nil, errExecNotFullPath(path)
	}
	// #nosec G204 -- the name passed the exec rules; the path is chosen by agent code, never by a Hub message.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = SanitizedChildEnv()
	return cmd, nil
}

// AgentPathCommandContextCombinedOutput is CommandContextCombinedOutput for a
// path chosen by agent code (see NewAgentPathCommandContext).
func AgentPathCommandContextCombinedOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd, err := NewAgentPathCommandContext(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	return CaptureCombinedOutput(cmd, DefaultCommandOutputLimit)
}

// AgentPathCommandContextOutput is CommandContextOutput for a path chosen by
// agent code (see NewAgentPathCommandContext).
func AgentPathCommandContextOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd, err := NewAgentPathCommandContext(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	return CaptureOutput(cmd, DefaultCommandOutputLimit)
}
