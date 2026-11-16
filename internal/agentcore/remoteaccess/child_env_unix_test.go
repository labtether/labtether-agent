//go:build unix

package remoteaccess

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Risk: the agent's API or enrollment token, set as a variable, reaches the
// program started for a desktop diagnostic probe. A stand-in on a scratch PATH records
// its environment.
func TestDesktopDiagnosticProbeGetsTheSanitizedEnvironment(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "child.env")
	t.Setenv("PATH", dir)
	t.Setenv("LABTETHER_API_TOKEN", "ltqa-api-token")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "ltqa-enrollment-token")
	writeEnvStandIn(t, dir, "pgrep", envFile, "4242 Xvfb :99")
	if _, err := diagnosticCommandOutput("pgrep", "-a", "Xvfb"); err != nil {
		t.Fatalf("diagnosticCommandOutput: %v", err)
	}
	checkChildEnvFile(t, "desktop diagnostic pgrep", envFile)
}

// writeEnvStandIn writes a program called name into dir that saves its
// environment to envFile and prints one line per output argument.
func writeEnvStandIn(t *testing.T, dir, name, envFile string, output ...string) {
	t.Helper()
	script := "#!/bin/sh\n/usr/bin/env > '" + envFile + "'\nprintf '%s\\n' '" + strings.Join(output, "' '") + "'\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

func checkChildEnvFile(t *testing.T, site, envFile string) {
	t.Helper()
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("%s: the stand-in did not run: %v", site, err)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		name, _, _ := strings.Cut(line, "=")
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("%s child environment names: %s", site, strings.Join(names, " "))
	if strings.Contains(string(data), "ltqa-api-token") || strings.Contains(string(data), "ltqa-enrollment-token") {
		t.Errorf("%s: a token reached the child", site)
	}
}
