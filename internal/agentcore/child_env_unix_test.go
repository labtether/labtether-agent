//go:build unix

package agentcore

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Risk: the agent's API or enrollment token, set as a variable, reaches a
// program the agent starts for a reboot or a self-update trial run. A
// stand-in program records its environment; nothing real is rebooted.
func TestPowerAndTrialRunChildrenGetTheSanitizedEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LABTETHER_API_TOKEN", "ltqa-api-token")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "ltqa-enrollment-token")

	powerEnv := filepath.Join(dir, "power.env")
	power := writeEnvStandIn(t, dir, "systemctl", powerEnv, "")
	if err := (execPowerCommandRunner{}).Run(context.Background(), power, "reboot", "--no-wall"); err != nil {
		t.Fatalf("power runner: %v", err)
	}
	checkChildEnvFile(t, "power", powerEnv)

	trialEnv := filepath.Join(dir, "trial.env")
	staged := writeEnvStandIn(t, dir, "labtether-agent.new", trialEnv, "labtether-agent 9.8.7")
	if err := trialRunStagedExecutable(staged, "v9.8.7"); err != nil {
		t.Fatalf("trial run: %v", err)
	}
	checkChildEnvFile(t, "self-update trial run", trialEnv)
}

// writeEnvStandIn writes a program that saves its environment to envFile and
// prints output.
func writeEnvStandIn(t *testing.T, dir, name, envFile, output string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n/usr/bin/env > '" + envFile + "'\nprintf '%s\\n' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
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
