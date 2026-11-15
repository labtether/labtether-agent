package securityruntime

import (
	"slices"
	"strings"
	"testing"
)

type childEnvCases struct {
	Filter []struct {
		Env     map[string]string `json:"env"`
		Removed []string          `json:"removed"`
		Kept    []string          `json:"kept"`
		From    string            `json:"from"`
	} `json:"filter"`
	Keys []struct {
		Allowed []string `json:"allowed"`
		Refused []string `json:"refused"`
		From    string   `json:"from"`
	} `json:"keys"`
}

// Risk: a credential in the agent's environment reaches a started command.
// testdata/child_env_cases.json "filter".
func TestSharedChildEnvFilterCases(t *testing.T) {
	var cases childEnvCases
	loadCases(t, "child_env_cases.json", &cases)
	for index, tc := range cases.Filter {
		for key, value := range tc.Env {
			t.Setenv(key, value)
		}
		env := SanitizedChildEnv()
		keys := make([]string, 0, len(env))
		for _, entry := range env {
			key, _, _ := strings.Cut(entry, "=")
			keys = append(keys, key)
		}
		for _, removed := range tc.Removed {
			if slices.Contains(keys, removed) {
				t.Errorf("filter[%d]: child environment kept %s", index, removed)
			}
		}
		for _, kept := range tc.Kept {
			if !slices.Contains(env, kept) {
				t.Errorf("filter[%d]: child environment lost %q", index, kept)
			}
		}
	}
}

// Risk: a new or uncommon variable is passed on by guesswork instead of
// failing closed. testdata/child_env_cases.json "keys".
func TestSharedChildEnvKeyCases(t *testing.T) {
	var cases childEnvCases
	loadCases(t, "child_env_cases.json", &cases)
	for _, tc := range cases.Keys {
		for _, key := range tc.Allowed {
			if !isAllowedChildEnvKey(key) {
				t.Errorf("expected %q to be allowed", key)
			}
		}
		for _, key := range tc.Refused {
			if isAllowedChildEnvKey(key) {
				t.Errorf("expected %q to fail closed", key)
			}
		}
	}
}
