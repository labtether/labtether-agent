package backends

import (
	"strings"
	"unicode/utf16"
)

// wevtutilUnicodeArg makes wevtutil write UTF-16. Without it, output sent to a
// pipe is in the console code page, which turns every character outside it
// (accents, CJK, and the left-to-right marks Windows puts around dates) into "?".
const wevtutilUnicodeArg = "/uni:true"

// decodeWevtutilOutput turns wevtutil's UTF-16LE output into UTF-8 text and
// drops the invisible left-to-right and right-to-left marks, so dates read and
// search as typed. Output that is not UTF-16 (older wrappers, recorded
// fixtures) is returned unchanged.
func decodeWevtutilOutput(raw []byte) []byte {
	body := raw
	switch {
	case len(body) >= 2 && body[0] == 0xFF && body[1] == 0xFE:
		body = body[2:]
	case len(body) >= 2 && body[0] != 0 && body[1] == 0:
	default:
		return raw
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = uint16(body[2*i]) | uint16(body[2*i+1])<<8
	}
	text := strings.Map(func(r rune) rune {
		if r == '\u200e' || r == '\u200f' {
			return -1
		}
		return r
	}, string(utf16.Decode(units)))
	return []byte(text)
}
