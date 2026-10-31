//go:build linux

package agentcore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// serviceManagerRestart returns a restart through systemd when systemd runs
// this agent as a service, or nil. systemd stops the agent with SIGTERM, so
// it shuts down cleanly, then starts it again whatever its Restart= policy.
func serviceManagerRestart() func() error {
	if nativeAppManaged() || strings.TrimSpace(os.Getenv("INVOCATION_ID")) == "" {
		return nil
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil
	}
	unit, userUnit := systemdServiceFromCgroup(string(data))
	if unit == "" {
		return nil
	}
	args := []string{"--no-block", "restart", unit}
	if userUnit {
		args = append([]string{"--user"}, args...)
	}
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := securityruntime.CommandContextCombinedOutput(ctx, "systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// systemdServiceFromCgroup returns the service unit that holds this process,
// from /proc/self/cgroup ("0::/system.slice/labtether-agent.service" with
// cgroup v2, "1:name=systemd:/..." with v1). Only the last path element
// counts, so a process inside a scope or a user manager is never mistaken
// for the service that contains it.
func systemdServiceFromCgroup(data string) (unit string, userUnit bool) {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 || (parts[0] != "0" && parts[1] != "name=systemd") {
			continue
		}
		path := parts[2]
		name := path[strings.LastIndex(path, "/")+1:]
		if !strings.HasSuffix(name, ".service") || strings.HasPrefix(name, "user@") {
			continue
		}
		return name, strings.Contains(path, "/user@")
	}
	return "", false
}
