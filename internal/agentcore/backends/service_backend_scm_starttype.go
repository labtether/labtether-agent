package backends

import (
	"strings"

	"github.com/labtether/protocol"
)

// Windows service start types (QUERY_SERVICE_CONFIG.dwStartType).
const (
	scStartBoot     = 0
	scStartSystem   = 1
	scStartAuto     = 2
	scStartDemand   = 3
	scStartDisabled = 4
)

// scStartTypeWord names a start type the way the Services page reads the
// "enabled" column: started with Windows, started on demand, or never.
func scStartTypeWord(startType uint32) string {
	switch startType {
	case scStartBoot, scStartSystem, scStartAuto:
		return "enabled"
	case scStartDemand:
		return "manual"
	case scStartDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// applyServiceStartTypes fills each service's Enabled from lookup, which maps
// service names to start-type words. Services lookup does not know keep
// "unknown".
func applyServiceStartTypes(services []protocol.ServiceInfo, lookup func([]string) map[string]string) {
	if lookup == nil || len(services) == 0 {
		return
	}
	names := make([]string, 0, len(services))
	for _, svc := range services {
		names = append(names, svc.Name)
	}
	words := lookup(names)
	for i := range services {
		if word := words[strings.ToLower(services[i].Name)]; word != "" {
			services[i].Enabled = word
		}
	}
}

// scErrorText puts sc.exe's failure on one line. sc.exe writes the code on one
// line and its meaning after a blank line ("OpenService FAILED 1060:", then
// "The specified service does not exist as an installed service."), and only
// the first line used to reach the person.
func scErrorText(output string) string {
	lines := strings.Fields(strings.ReplaceAll(output, "\r", ""))
	return strings.Join(lines, " ")
}
