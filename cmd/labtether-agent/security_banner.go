package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// logSecurityModeBanner surfaces, at startup, any security-control toggle that
// downgrades the agent's default posture. Operators who intentionally opt out
// of a control should see it reflected in their logs on every boot so the
// state is not silently inherited across restarts or forgotten by on-call.
func logSecurityModeBanner() {
	warnings := []string{}

	execMode := boolEnv("LABTETHER_EXEC_ALLOWLIST_MODE", true)
	execRisk := boolEnv("LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK", false)
	if !execMode {
		if execRisk {
			warnings = append(warnings, "exec allowlist DISABLED (LABTETHER_EXEC_ALLOWLIST_MODE=false, ACCEPT_RISK=true) — any binary basename may be spawned")
		} else {
			warnings = append(warnings, "exec allowlist is set to disabled but LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK=true is not set — exec requests will be REFUSED until the accept-risk flag is added")
		}
	}

	shellMode := boolEnv("LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE", true)
	shellRisk := boolEnv("LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK", false)
	if !shellMode {
		if shellRisk {
			warnings = append(warnings, "shell allowlist DISABLED (LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE=false, ACCEPT_RISK=true) — only the small blocked-token list guards shell invocations")
		} else {
			warnings = append(warnings, "shell allowlist is set to disabled but LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK=true is not set — shell requests will be REFUSED until the accept-risk flag is added")
		}
	}

	trustedKey := strings.TrimSpace(os.Getenv("LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY"))
	acceptUnsigned := boolEnv("LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED", false)
	if trustedKey == "" && acceptUnsigned {
		warnings = append(warnings, "self-update signature verification DISABLED (LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED=true) — agent will accept any binary the hub advertises")
	}

	for _, w := range warnings {
		log.Printf("labtether-agent: SECURITY WARNING: %s", w)
	}
}

func boolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}
