package securityruntime

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type parseCase struct {
	In       string   `json:"in"`
	Repeat   string   `json:"repeat"`
	Count    int      `json:"count"`
	Args     []string `json:"args"`
	ArgCount int      `json:"arg_count"`
	Error    string   `json:"error"`
	From     string   `json:"from"`
}

type commandCases struct {
	Parse []parseCase `json:"parse"`
	Exec  []caseGroup `json:"exec"`
	Shell []caseGroup `json:"shell"`
}

func loadCommandCases(t *testing.T) commandCases {
	var cases commandCases
	loadCases(t, "command_cases.json", &cases)
	return cases
}

// Risk: the command line splits differently, so a quoted operator runs or a
// literal argument changes. testdata/command_cases.json "parse".
func TestSharedParseCases(t *testing.T) {
	for index, tc := range loadCommandCases(t).Parse {
		input := tc.In
		if tc.Repeat != "" {
			input = strings.Repeat(tc.Repeat, tc.Count)
		}
		label := fmt.Sprintf("parse[%d] %.60q", index, input)
		args, err := ParseCommandLine(input)
		switch {
		case tc.Error != "":
			checkWant(t, label, err, tc.Error)
		case err != nil:
			t.Errorf("%s: error %q, want arguments", label, err)
		case tc.Args != nil && !slices.Equal(args, tc.Args):
			t.Errorf("%s: args %q, want %q", label, args, tc.Args)
		case tc.ArgCount != 0 && len(args) != tc.ArgCount:
			t.Errorf("%s: %d args, want %d", label, len(args), tc.ArgCount)
		}
	}
}

// Risk: a program off the exec allowlist starts, or a blocked one does.
// testdata/command_cases.json "exec".
func TestSharedExecCases(t *testing.T) {
	for _, group := range loadCommandCases(t).Exec {
		t.Run(group.Group, func(t *testing.T) {
			applyPolicyEnv(t, group.Env)
			for _, tc := range group.Cases {
				checkWant(t, fmt.Sprintf("%q", tc.In), ValidateExecBinary(tc.In), tc.Want)
			}
		})
	}
}

// Risk: a Hub command escapes the shell allowlist, the blocked words or the
// read-only reader rules. testdata/command_cases.json "shell".
func TestSharedShellCases(t *testing.T) {
	for _, group := range loadCommandCases(t).Shell {
		t.Run(group.Group, func(t *testing.T) {
			if slices.Contains(group.SkipOS, runtime.GOOS) {
				t.Skipf("case group does not apply on %s", runtime.GOOS)
			}
			applyPolicyEnv(t, group.Env)
			paths := casePaths(t)
			protect := make([]string, 0, len(group.Protect))
			for _, path := range group.Protect {
				protect = append(protect, paths.Replace(path))
			}
			SetProtectedReadPaths(protect...)
			t.Cleanup(func() { SetProtectedReadPaths() })
			for _, tc := range group.Cases {
				command := paths.Replace(tc.In)
				var err error
				switch group.Check {
				case "validated":
					_, err = NewValidatedShellCommandContext(context.Background(), command)
				case "":
					err = ValidateShellCommand(command)
				default:
					t.Fatalf("unknown check %q", group.Check)
				}
				checkWant(t, fmt.Sprintf("%q", command), err, paths.Replace(tc.Want))
			}
		})
	}
}
