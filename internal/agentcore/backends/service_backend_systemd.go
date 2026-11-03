package backends

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const (
	linuxServiceActionTimeout = 30 * time.Second
	linuxServiceListTimeout   = 15 * time.Second
)

// LinuxServiceBackend implements ServiceBackend using systemd.
type LinuxServiceBackend struct{}

// RunLinuxServiceCommand is the function used to run systemctl commands. Overridable for tests.
var RunLinuxServiceCommand = securityruntime.CommandContextCombinedOutput

// ListServices lists systemd services.
func (LinuxServiceBackend) ListServices() ([]protocol.ServiceInfo, error) {
	enabledMap, err := collectEnabledStatesLinux()
	if err != nil {
		enabledMap = map[string]string{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), linuxServiceListTimeout)
	defer cancel()

	out, err := RunLinuxServiceCommand(
		ctx,
		"systemctl", "list-units",
		"--type=service", "--all",
		"--no-pager", "--plain", "--no-legend",
	)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("systemctl list-units timed out")
		}
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}

	var services []protocol.ServiceInfo
	listed := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// UNIT LOAD ACTIVE SUB DESCRIPTION...
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		unit := fields[0]
		loadState := fields[1]
		activeState := fields[2]
		subState := fields[3]
		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}
		name := strings.TrimSuffix(unit, ".service")

		services = append(services, protocol.ServiceInfo{
			Name:        name,
			Description: description,
			ActiveState: activeState,
			SubState:    subState,
			Enabled:     enabledMap[unit],
			LoadState:   loadState,
		})
		listed[unit] = true
	}

	return append(services, unloadedServiceUnits(enabledMap, listed)...), nil
}

// unloadedServiceUnits returns installed services that list-units leaves out
// because systemd has not loaded them since boot: a disabled service that has
// not run is one. Without them a stopped, disabled service could not be found
// to start or enable again. Static, masked, alias and template units are left
// out, as nothing can enable or start them by name.
func unloadedServiceUnits(enabledMap map[string]string, listed map[string]bool) []protocol.ServiceInfo {
	units := make([]string, 0, len(enabledMap))
	for unit, state := range enabledMap {
		switch state {
		case "enabled", "enabled-runtime", "disabled", "indirect", "linked", "linked-runtime":
		default:
			continue
		}
		if listed[unit] || !strings.HasSuffix(unit, ".service") || strings.Contains(unit, "@.") {
			continue
		}
		units = append(units, unit)
	}
	sort.Strings(units)
	out := make([]protocol.ServiceInfo, 0, len(units))
	for _, unit := range units {
		out = append(out, protocol.ServiceInfo{
			Name:        strings.TrimSuffix(unit, ".service"),
			ActiveState: "inactive",
			SubState:    "dead",
			Enabled:     enabledMap[unit],
		})
	}
	return out
}

// PerformAction performs a systemctl action on a named service.
func (LinuxServiceBackend) PerformAction(action, service string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), linuxServiceActionTimeout)
	defer cancel()

	out, err := RunLinuxServiceCommand(ctx, "systemctl", action, service)
	output := strings.TrimSpace(string(out))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("systemctl timed out")
		}
		return output, err
	}
	return output, nil
}

func collectEnabledStatesLinux() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := RunLinuxServiceCommand(
		ctx,
		"systemctl", "list-unit-files",
		"--type=service",
		"--no-pager", "--plain", "--no-legend",
	)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("systemctl list-unit-files timed out")
		}
		return nil, fmt.Errorf("systemctl list-unit-files: %w", err)
	}

	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		result[fields[0]] = fields[1]
	}
	return result, nil
}
