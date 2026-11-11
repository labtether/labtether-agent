package backends

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// RunLaunchctlPrintDisabled runs `launchctl print-disabled DOMAIN`. Overridable for tests.
var RunLaunchctlPrintDisabled = func(ctx context.Context, domain string) ([]byte, error) {
	return securityruntime.CommandContextCombinedOutput(ctx, "launchctl", "print-disabled", domain)
}

// launchdDomains are the domains whose overrides apply to the jobs
// `launchctl list` shows for this user: the GUI session first, then the
// background user domain; root sees the system domain.
func launchdDomains() []string {
	if os.Geteuid() == 0 {
		return []string{"system"}
	}
	uid := strconv.Itoa(os.Getuid())
	return []string{"gui/" + uid, "user/" + uid}
}

// ParseLaunchctlPrintDisabled reads the "disabled services" block of
// `launchctl print-disabled`. Newer macOS writes "=> disabled|enabled",
// older releases "=> true|false" (true means disabled).
func ParseLaunchctlPrintDisabled(raw string) map[string]bool {
	disabled := map[string]bool{}
	inBlock := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "disabled services = {"):
			inBlock = true
			continue
		case line == "}":
			inBlock = false
			continue
		case !inBlock:
			continue
		}
		label, value, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}
		label = strings.Trim(strings.TrimSpace(label), `"`)
		value = strings.ToLower(strings.TrimSpace(value))
		if label != "" {
			disabled[label] = value == "disabled" || value == "true"
		}
	}
	return disabled
}

// applyLaunchdEnabled marks each listed job enabled or disabled. A job
// `launchctl list` shows is loaded, so it counts as enabled unless launchd
// holds a "disabled" override for it. Without any readable domain the jobs
// keep "unknown".
func applyLaunchdEnabled(ctx context.Context, services []protocol.ServiceInfo) {
	disabled := map[string]bool{}
	read := false
	for _, domain := range launchdDomains() {
		out, err := RunLaunchctlPrintDisabled(ctx, domain)
		if err != nil {
			continue
		}
		read = true
		for label, off := range ParseLaunchctlPrintDisabled(string(out)) {
			if _, seen := disabled[label]; !seen {
				disabled[label] = off
			}
		}
	}
	if !read {
		return
	}
	for i := range services {
		if disabled[services[i].Name] {
			services[i].Enabled = "disabled"
		} else {
			services[i].Enabled = "enabled"
		}
	}
}
