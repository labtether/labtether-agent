//go:build unix

package system

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Risk: the agent's API or enrollment token, set as a variable, reaches the
// program started for the process or disk list. A stand-in on a scratch PATH records
// its environment.
func TestProcessAndDiskListsGetTheSanitizedEnvironment(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "child.env")
	t.Setenv("PATH", dir)
	t.Setenv("LABTETHER_API_TOKEN", "ltqa-api-token")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "ltqa-enrollment-token")
	writeEnvStandIn(t, dir, "ps", envFile, "root 1 0.0 0.1 1000 /sbin/init")
	if _, err := CollectProcesses(); err != nil {
		t.Fatalf("CollectProcesses: %v", err)
	}
	checkChildEnvFile(t, "process list ps", envFile)

	dfEnv := filepath.Join(dir, "df.env")
	writeEnvStandIn(t, dir, "df", dfEnv, "Filesystem 1024-blocks Used Available Capacity Mounted on", "/dev/sda1 1000 500 500 50% /")
	if _, err := collectMountsDF(); err != nil {
		t.Fatalf("collectMountsDF: %v", err)
	}
	checkChildEnvFile(t, "disk list df", dfEnv)
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
