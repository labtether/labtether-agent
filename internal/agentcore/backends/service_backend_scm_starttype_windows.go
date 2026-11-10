//go:build windows

package backends

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsServiceStartTypes reads each service's start type from the Service
// Control Manager. It asks only for query rights, so it works without admin.
// Names it cannot read are left out.
func windowsServiceStartTypes(names []string) map[string]string {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(manager)
	words := make(map[string]string, len(names))
	buf := make([]byte, 8192)
	for _, name := range names {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		service, err := windows.OpenService(manager, namePtr, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			continue
		}
		var needed uint32
		config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
		err = windows.QueryServiceConfig(service, config, uint32(len(buf)), &needed)
		if err == windows.ERROR_INSUFFICIENT_BUFFER && needed > uint32(len(buf)) {
			buf = make([]byte, needed)
			config = (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
			err = windows.QueryServiceConfig(service, config, uint32(len(buf)), &needed)
		}
		windows.CloseServiceHandle(service)
		if err == nil {
			words[strings.ToLower(name)] = scStartTypeWord(config.StartType)
		}
	}
	return words
}
