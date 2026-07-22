package packagepolicy

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeAndValidateAcceptsPackageEcosystemNames(t *testing.T) {
	t.Parallel()

	input := []string{
		" curl ",
		"curl",
		"@scope/package@1.2.3",
		"python@3.12",
		"homebrew/cask/google-chrome",
		"libssl3:amd64=3.0.2-0ubuntu1.18",
		"kernel-default=6.4.0-1.x86_64",
		"Microsoft.PowerShell",
		"pkg=2:1.0~rc1-1",
	}
	want := []string{
		"curl",
		"@scope/package@1.2.3",
		"python@3.12",
		"homebrew/cask/google-chrome",
		"libssl3:amd64=3.0.2-0ubuntu1.18",
		"kernel-default=6.4.0-1.x86_64",
		"Microsoft.PowerShell",
		"pkg=2:1.0~rc1-1",
	}

	got, err := NormalizeAndValidate(input)
	if err != nil {
		t.Fatalf("NormalizeAndValidate: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized packages = %#v, want %#v", got, want)
	}
}

func TestNormalizeAndValidateRejectsUnsafePackageTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		packages []string
	}{
		{name: "empty", packages: []string{""}},
		{name: "whitespace only", packages: []string{"   "}},
		{name: "option", packages: []string{"-o"}},
		{name: "long option", packages: []string{"--config"}},
		{name: "newline", packages: []string{"bad\nname"}},
		{name: "nul", packages: []string{"bad\x00name"}},
		{name: "tab", packages: []string{"bad\tname"}},
		{name: "shell punctuation", packages: []string{"bad;name"}},
		{name: "embedded space", packages: []string{"bad name"}},
		{name: "url shape", packages: []string{"https://example.invalid/pkg"}},
		{name: "path traversal", packages: []string{"foo/../../bar"}},
		{name: "windows path", packages: []string{"C:/temp/pkg"}},
		{name: "overlong", packages: []string{strings.Repeat("a", MaxPackageNameBytes+1)}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeAndValidate(test.packages); err == nil {
				t.Fatalf("NormalizeAndValidate(%q) unexpectedly succeeded", test.packages)
			}
		})
	}
}

func TestNormalizeAndValidateRejectsExcessivePackageCountBeforeDeduplication(t *testing.T) {
	t.Parallel()

	packages := make([]string, MaxPackageCount+1)
	for index := range packages {
		packages[index] = "curl"
	}
	if _, err := NormalizeAndValidate(packages); err == nil {
		t.Fatal("expected excessive package count to be rejected")
	}
}

func TestNormalizeAndValidateAllowsEmptyListForUpgradeAll(t *testing.T) {
	t.Parallel()

	got, err := NormalizeAndValidate(nil)
	if err != nil {
		t.Fatalf("NormalizeAndValidate(nil): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("normalized empty list = %#v", got)
	}
}
