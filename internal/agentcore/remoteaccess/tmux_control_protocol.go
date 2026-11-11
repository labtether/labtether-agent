package remoteaccess

import (
	"bytes"
	"strconv"
	"strings"
)

// The control-mode terminal needs tmux 3.2 or newer. 3.0 added send-keys -H;
// 3.2 added new-session -e and, the part that decides it, a limit on how much
// output tmux keeps for a control client (pause-after). Before 3.2 a client
// that falls behind makes the tmux server grow without bound.
const (
	tmuxControlMinMajor = 3
	tmuxControlMinMinor = 2
)

// tmuxSupportsControl reads `tmux -V` ("tmux 3.5a", "tmux next-3.6"). A
// version it cannot read keeps the PTY attach path.
func tmuxSupportsControl(versionOutput string) bool {
	fields := strings.Fields(versionOutput)
	if len(fields) < 2 || fields[0] != "tmux" {
		return false
	}
	majorText, rest, found := strings.Cut(strings.TrimPrefix(fields[1], "next-"), ".")
	if !found {
		return false
	}
	major, err := strconv.Atoi(majorText)
	if err != nil {
		return false
	}
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	minor, err := strconv.Atoi(rest[:digits])
	if err != nil {
		return false
	}
	return major > tmuxControlMinMajor || (major == tmuxControlMinMajor && minor >= tmuxControlMinMinor)
}

// tmuxGuardStamp returns the "time number flags" part of a %begin, %end or
// %error line. A reply block ends at the %end or %error with the same stamp,
// so a captured screen line that happens to start with %end does not end it.
func tmuxGuardStamp(line []byte, kind string) ([]byte, bool) {
	if !bytes.HasPrefix(line, []byte(kind)) || len(line) <= len(kind) || line[len(kind)] != ' ' {
		return nil, false
	}
	return line[len(kind)+1:], true
}

// tmuxGuardIsOwn reports whether a block answers a command this client sent.
// The last field is a flag word; bit 0 is set for commands read from the
// control client, and clear for the attach command and for hooks.
func tmuxGuardIsOwn(stamp []byte) bool {
	idx := bytes.LastIndexByte(stamp, ' ')
	flags, err := strconv.Atoi(string(stamp[idx+1:]))
	return err == nil && flags&1 == 1
}

// tmuxOutputLine splits "%output %1 data" and "%extended-output %1 12 : data"
// (the form tmux uses once pause-after is set) into the pane and its data.
func tmuxOutputLine(line []byte) (pane, data []byte, ok bool) {
	extended := false
	switch {
	case bytes.HasPrefix(line, []byte("%output ")):
		line = line[len("%output "):]
	case bytes.HasPrefix(line, []byte("%extended-output ")):
		line = line[len("%extended-output "):]
		extended = true
	default:
		return nil, nil, false
	}
	space := bytes.IndexByte(line, ' ')
	if space < 0 {
		return line, nil, !extended
	}
	pane, data = line[:space], line[space+1:]
	if !extended {
		return pane, data, true
	}
	// Fields between the pane and " : " are the age and room for more.
	if bytes.HasPrefix(data, []byte(": ")) {
		return pane, data[2:], true
	}
	sep := bytes.Index(data, []byte(" : "))
	if sep < 0 {
		return nil, nil, false
	}
	return pane, data[sep+3:], true
}

// appendTmuxUnescaped undoes control mode's output escaping: bytes below
// space and the backslash arrive as a backslash and three octal digits, all
// other bytes as themselves.
func appendTmuxUnescaped(dst, src []byte) []byte {
	for len(src) > 0 {
		slash := bytes.IndexByte(src, '\\')
		if slash < 0 {
			return append(dst, src...)
		}
		dst = append(dst, src[:slash]...)
		src = src[slash:]
		if len(src) >= 4 && isOctal(src[1]) && isOctal(src[2]) && isOctal(src[3]) {
			dst = append(dst, (src[1]-'0')<<6|(src[2]-'0')<<3|(src[3]-'0'))
			src = src[4:]
			continue
		}
		dst = append(dst, '\\')
		src = src[1:]
	}
	return dst
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// tmuxSendKeysChunk is how many input bytes go into one send-keys line.
const tmuxSendKeysChunk = 512

// tmuxSendKeysLines turns typed bytes into send-keys -H lines. -H writes each
// byte to the pane as it is, so UTF-8, escape sequences and control keys reach
// the program unchanged. Lines are sent in order; tmux runs them in order.
func tmuxSendKeysLines(pane string, data []byte) []string {
	const hexDigits = "0123456789abcdef"
	lines := make([]string, 0, len(data)/tmuxSendKeysChunk+1)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > tmuxSendKeysChunk {
			chunk = chunk[:tmuxSendKeysChunk]
		}
		data = data[len(chunk):]
		var line strings.Builder
		line.Grow(len("send-keys -t  -H") + len(pane) + 3*len(chunk))
		line.WriteString("send-keys -t ")
		line.WriteString(pane)
		line.WriteString(" -H")
		for _, b := range chunk {
			line.WriteByte(' ')
			line.WriteByte(hexDigits[b>>4])
			line.WriteByte(hexDigits[b&0x0f])
		}
		lines = append(lines, line.String())
	}
	return lines
}

// tmuxQuote makes one argument of a control-mode command line. Inside single
// quotes tmux takes every character as it is.
func tmuxQuote(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// tmuxLiteralFormat keeps tmux from expanding #{...} or #(...) in a value it
// treats as a format, such as a start folder.
func tmuxLiteralFormat(value string) string {
	return strings.ReplaceAll(value, "#", "##")
}

// tmuxSanitizedSessionName mirrors what tmux before 3.7 does to a session
// name: a dot or a colon becomes an underscore.
func tmuxSanitizedSessionName(name string) string {
	return strings.NewReplacer(".", "_", ":", "_").Replace(name)
}
