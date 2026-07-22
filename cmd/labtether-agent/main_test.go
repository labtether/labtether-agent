package main

import (
	"testing"

	"github.com/labtether/labtether-agent/internal/agentcore"
)

func TestApplyLinkedVersion(t *testing.T) {
	t.Run("linked release version overrides build metadata", func(t *testing.T) {
		cfg := applyLinkedVersion(agentcore.RuntimeConfig{Version: "git:abcdef"}, "  v1.2.3  ")
		if cfg.Version != "v1.2.3" {
			t.Fatalf("Version = %q, want v1.2.3", cfg.Version)
		}
	})

	t.Run("blank linked version preserves development metadata", func(t *testing.T) {
		cfg := applyLinkedVersion(agentcore.RuntimeConfig{Version: "git:abcdef"}, "  ")
		if cfg.Version != "git:abcdef" {
			t.Fatalf("Version = %q, want git:abcdef", cfg.Version)
		}
	})
}

func TestSplitRuntimeArgs(t *testing.T) {
	cliArgs, forceConsole := splitRuntimeArgs([]string{" --CONSOLE ", "settings", "show"})
	if !forceConsole {
		t.Fatal("forceConsole = false, want true")
	}
	if len(cliArgs) != 2 || cliArgs[0] != "settings" || cliArgs[1] != "show" {
		t.Fatalf("cliArgs = %#v, want settings show", cliArgs)
	}
}
