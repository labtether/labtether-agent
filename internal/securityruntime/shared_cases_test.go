package securityruntime

// The command, child-environment and output cases live in testdata/*.json
// so the Rust agent (rust/crates/security/tests) runs the same cases. A case
// names the Go test it came from, or "added".

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const allowWant = "allow"

var policyEnvKeys = []string{
	envExecAllowlistMode, envExecAllowlistAcceptRisk, envExecAllowedBinaries, envExecBlockedBinaries,
	envShellAllowlistMode, envShellAllowlistAcceptRisk, envShellAllowlistPrefixes, envShellBlockedSubstrings,
}

type policyCase struct {
	In   string `json:"in"`
	Want string `json:"want"`
	From string `json:"from"`
}

type caseGroup struct {
	Group   string            `json:"group"`
	Env     map[string]string `json:"env"`
	Protect []string          `json:"protect"`
	SkipOS  []string          `json:"skip_os"`
	Check   string            `json:"check"`
	Files   []string          `json:"files"`
	Links   map[string]string `json:"links"`
	Path    *string           `json:"path"`
	Cases   []policyCase      `json:"cases"`
}

func loadCases(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// applyPolicyEnv sets every policy variable: the group's value, or empty
// (which the policy reads as unset) for the rest.
func applyPolicyEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for key := range env {
		if !slices.Contains(policyEnvKeys, key) {
			t.Fatalf("unknown policy variable %q in case file", key)
		}
	}
	for _, key := range policyEnvKeys {
		t.Setenv(key, env[key])
	}
}

// casePaths makes {tmp}, {state} (holding agent-token) and {link} (a
// symlink to {state}) and returns a replacer for those placeholders.
func casePaths(t *testing.T) *strings.Replacer {
	t.Helper()
	tmp := t.TempDir()
	state := filepath.Join(tmp, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "agent-token"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if runtime.GOOS != "windows" {
		if err := os.Symlink(state, link); err != nil {
			t.Fatal(err)
		}
	}
	return strings.NewReplacer("{state}", state, "{link}", link, "{tmp}", tmp)
}

// applyGroupFiles makes the group's programs (small executable scripts) and
// links, then sets PATH when the group names one. Paths use the casePaths
// placeholders.
func applyGroupFiles(t *testing.T, paths *strings.Replacer, group caseGroup) {
	t.Helper()
	for _, file := range group.Files {
		path := paths.Replace(file)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range group.Links {
		link = paths.Replace(link)
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(paths.Replace(target), link); err != nil {
			t.Fatal(err)
		}
	}
	if group.Path != nil {
		t.Setenv("PATH", paths.Replace(*group.Path))
	}
}

func checkWant(t *testing.T, label string, err error, want string) {
	t.Helper()
	switch {
	case want == allowWant && err != nil:
		t.Errorf("%s: refused with %q, want allowed", label, err)
	case want != allowWant && err == nil:
		t.Errorf("%s: allowed, want %q", label, want)
	case want != allowWant && err.Error() != want:
		t.Errorf("%s: error %q, want %q", label, err, want)
	}
}
