//go:build windows

package securityruntime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Risk: on Windows a program given with a folder runs a planted copy under an
// allowlisted name, or a drive-relative or rooted path slips past the rule.
func TestExecPathRuleOnWindows(t *testing.T) {
	applyPolicyEnv(t, nil)
	found, err := exec.LookPath("cmd.exe")
	if err != nil {
		t.Fatalf("cmd.exe not found in PATH: %v", err)
	}
	copied := filepath.Join(t.TempDir(), "cmd.exe")
	data, err := os.ReadFile(found)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copied, data, 0o700); err != nil {
		t.Fatal(err)
	}
	notFull := func(name string) string {
		return fmt.Sprintf("command %q must be a program name or a full path", name)
	}
	for name, want := range map[string]string{
		found:                              allowWant,
		strings.ToUpper(found):             allowWant,
		strings.TrimSuffix(found, ".exe"):  allowWant,
		"cmd.exe":                          allowWant,
		copied:                             fmt.Sprintf("command %q is not the %q found in PATH", copied, "cmd"),
		"C:cmd.exe":                        notFull("C:cmd.exe"),
		`.\cmd.exe`:                        notFull(`.\cmd.exe`),
		`\Windows\System32\cmd.exe`:        notFull(`\Windows\System32\cmd.exe`),
		filepath.VolumeName(found) + "cmd": notFull(filepath.VolumeName(found) + "cmd"),
	} {
		checkWant(t, fmt.Sprintf("%q", name), ValidateExecBinary(name), want)
	}
	cmd, err := NewCommandContext(context.Background(), strings.ToUpper(found), "/c", "echo", "ok")
	if err != nil {
		t.Fatal(err)
	}
	// The lookup keeps the letter case of the name as given; the file is the same.
	if !strings.EqualFold(cmd.Path, found) {
		t.Errorf("started %q, want the PATH program %q", cmd.Path, found)
	}
	if out, err := CaptureCombinedOutput(cmd, 1024); err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Errorf("run: %q %v", out, err)
	}
}
