//go:build linux

package agentcore

import "testing"

// The restart must name the agent's own service and never a unit that only
// contains it, such as a user's service manager.
func TestSystemdServiceFromCgroup(t *testing.T) {
	for _, tc := range []struct {
		cgroup   string
		unit     string
		userUnit bool
	}{
		{"0::/system.slice/labtether-agent.service\n", "labtether-agent.service", false},
		{"12:pids:/system.slice/x\n1:name=systemd:/system.slice/labtether-agent.service\n", "labtether-agent.service", false},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/labtether-agent.service\n", "labtether-agent.service", true},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-terminal-1.scope\n", "", false},
		{"0::/user.slice/user-1000.slice/user@1000.service\n", "", false},
		{"0::/user.slice/user-1000.slice/session-3.scope\n", "", false},
		{"0::/\n", "", false},
	} {
		unit, userUnit := systemdServiceFromCgroup(tc.cgroup)
		if unit != tc.unit || userUnit != tc.userUnit {
			t.Errorf("%q -> %q user=%v, want %q user=%v", tc.cgroup, unit, userUnit, tc.unit, tc.userUnit)
		}
	}
}
