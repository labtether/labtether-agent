//go:build windows

package system

import (
	"strings"
	"unsafe"

	"github.com/labtether/protocol"
	"golang.org/x/sys/windows"
)

const (
	wtsUserName                     = 5
	wtsDomainName                   = 7
	wtsClientName                   = 10
	wtsCurrentServer windows.Handle = 0
)

var (
	wtsapi32DLL                    = windows.NewLazySystemDLL("wtsapi32.dll")
	wtsQuerySessionInformationProc = wtsapi32DLL.NewProc("WTSQuerySessionInformationW")
)

func collectUserSessionsWindows() ([]protocol.UserSession, error) {
	var entries *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServer, 0, 1, &entries, &count); err != nil {
		return nil, err
	}
	if entries == nil || count == 0 {
		return nil, nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(entries)))

	items := unsafe.Slice(entries, int(count))
	sessions := make([]protocol.UserSession, 0, len(items))
	for _, item := range items {
		if !windowsSessionIsLoggedIn(item.State) {
			continue
		}
		username := strings.TrimSpace(wtsSessionString(item.SessionID, wtsUserName))
		if username == "" {
			continue
		}
		domain := strings.TrimSpace(wtsSessionString(item.SessionID, wtsDomainName))
		if domain != "" {
			username = domain + `\` + username
		}
		terminal := ""
		if item.WindowStationName != nil {
			terminal = strings.TrimSpace(windows.UTF16PtrToString(item.WindowStationName))
		}
		sessions = append(sessions, protocol.UserSession{
			Username:    username,
			Terminal:    terminal,
			RemoteHost:  strings.TrimSpace(wtsSessionString(item.SessionID, wtsClientName)),
			SessionType: windowsSessionType(terminal),
			Display:     terminal,
		})
	}
	return sessions, nil
}

func windowsSessionIsLoggedIn(state uint32) bool {
	return state == windows.WTSActive || state == windows.WTSConnected || state == windows.WTSDisconnected
}

func windowsSessionType(station string) string {
	normalized := strings.ToLower(strings.TrimSpace(station))
	switch {
	case normalized == "console":
		return "console"
	case strings.HasPrefix(normalized, "rdp-"):
		return "rdp"
	default:
		return "windows"
	}
}

func wtsSessionString(sessionID uint32, infoClass uintptr) string {
	var buffer *uint16
	var size uint32
	result, _, _ := wtsQuerySessionInformationProc.Call(
		uintptr(wtsCurrentServer),
		uintptr(sessionID),
		infoClass,
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&size)),
	)
	if result == 0 || buffer == nil || size < 2 {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16ToString(unsafe.Slice(buffer, int(size/2)))
}
