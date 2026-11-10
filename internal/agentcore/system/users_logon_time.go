package system

import "time"

// windowsEpochOffset is the number of 100 ns intervals between 1601-01-01
// (the Windows FILETIME epoch) and 1970-01-01.
const windowsEpochOffset = 116444736000000000

// windowsLogonTime formats a session's FILETIME logon time as RFC 3339 UTC,
// the way the Users page and the other platforms report login times. Zero
// means Windows does not know the time.
func windowsLogonTime(filetime int64) string {
	if filetime <= windowsEpochOffset {
		return ""
	}
	return time.Unix(0, (filetime-windowsEpochOffset)*100).UTC().Format(time.RFC3339)
}
