package webservice

import (
	"strconv"
	"strings"
)

func strictDecimalInt(raw string) (int, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	for _, ch := range trimmed {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, false
	}
	return value, true
}
