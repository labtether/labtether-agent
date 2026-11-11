package remoteaccess

import "bytes"

// terminalQueryFilter removes the questions a program asks its terminal
// (cursor position, device attributes, colours, mode state) from shell output
// on its way to the browser.
//
// tmux sits between the program and the browser's terminal and answers these
// itself. If the browser saw them too it would answer a second time, and that
// second answer would arrive as typed text: stray characters at the prompt.
// With the questions removed, tmux is the only one that answers, as in any
// tmux session.
//
// An unfinished escape sequence is held until its end arrives, so a question
// split across two reads is still found. A terminal does nothing with half a
// sequence either, so holding it changes nothing a person sees.
type terminalQueryFilter struct {
	state byte
	held  []byte
}

const (
	queryGround byte = iota
	queryEscape
	queryCSI
	queryOSC
	queryOSCEscape
	queryDCS
	queryRequest
	queryRequestEscape
)

const (
	escByte = 0x1b
	// Longest sequence looked at. A longer one is not a question; it goes
	// through as it is.
	queryMaxCSIBytes     = 64
	queryMaxStringBytes  = 256
	queryMaxRequestBytes = 512
)

func (f *terminalQueryFilter) reset() {
	f.state = queryGround
	f.held = f.held[:0]
}

// apply appends data to dst without the questions in it.
func (f *terminalQueryFilter) apply(dst, data []byte) []byte {
	for len(data) > 0 {
		if f.state == queryGround {
			esc := bytes.IndexByte(data, escByte)
			if esc < 0 {
				return append(dst, data...)
			}
			dst = append(dst, data[:esc]...)
			data = data[esc+1:]
			f.begin()
			continue
		}
		dst = f.step(dst, data[0])
		data = data[1:]
	}
	return dst
}

func (f *terminalQueryFilter) begin() {
	f.held = append(f.held[:0], escByte)
	f.state = queryEscape
}

// pass lets the held bytes through and returns to plain text.
func (f *terminalQueryFilter) pass(dst []byte) []byte {
	dst = append(dst, f.held...)
	f.reset()
	return dst
}

func (f *terminalQueryFilter) step(dst []byte, c byte) []byte {
	switch f.state {
	case queryEscape:
		switch c {
		case '[':
			f.state = queryCSI
		case ']':
			f.state = queryOSC
		case 'P':
			f.state = queryDCS
		case escByte:
			dst = append(dst, f.held...)
			f.begin()
			return dst
		default:
			f.held = append(f.held, c)
			return f.pass(dst)
		}
		f.held = append(f.held, c)
	case queryCSI:
		switch {
		case c == escByte:
			dst = append(dst, f.held...)
			f.begin()
		case c >= 0x40 && c <= 0x7e:
			f.held = append(f.held, c)
			if isTerminalQueryCSI(f.held) {
				f.reset()
				return dst
			}
			return f.pass(dst)
		case c < 0x20 || c > 0x7e || len(f.held) >= queryMaxCSIBytes:
			f.held = append(f.held, c)
			return f.pass(dst)
		default:
			f.held = append(f.held, c)
		}
	case queryOSC:
		switch {
		case c == 0x07:
			return f.endOSC(dst, c)
		case c == escByte:
			f.state = queryOSCEscape
		case len(f.held) >= queryMaxStringBytes:
			f.held = append(f.held, c)
			return f.pass(dst)
		default:
			f.held = append(f.held, c)
		}
	case queryOSCEscape:
		if c == '\\' {
			return f.endOSC(dst, escByte, c)
		}
		// The string was cut short by a new escape sequence.
		dst = append(dst, f.held...)
		f.begin()
		return f.step(dst, c)
	case queryDCS:
		if c == escByte {
			dst = append(dst, f.held...)
			f.begin()
			return dst
		}
		f.held = append(f.held, c)
		if len(f.held) < 4 {
			return dst
		}
		// DECRQSS (ESC P $ q) and XTGETTCAP (ESC P + q) ask for a setting.
		if f.held[3] == 'q' && (f.held[2] == '$' || f.held[2] == '+') {
			f.state = queryRequest
			return dst
		}
		return f.pass(dst)
	case queryRequest:
		switch {
		case c == escByte:
			f.state = queryRequestEscape
		case len(f.held) >= queryMaxRequestBytes:
			f.held = append(f.held, c)
			return f.pass(dst)
		default:
			f.held = append(f.held, c)
		}
	case queryRequestEscape:
		if c == '\\' {
			f.reset()
			return dst
		}
		f.begin()
		return f.step(dst, c)
	}
	return dst
}

func (f *terminalQueryFilter) endOSC(dst []byte, terminator ...byte) []byte {
	if isTerminalQueryOSC(f.held[2:]) {
		f.reset()
		return dst
	}
	f.held = append(f.held, terminator...)
	return f.pass(dst)
}

// isTerminalQueryCSI reports whether a complete CSI sequence asks the
// terminal for a report. Sequences that only look similar (set cursor style,
// soft reset, title stack) are not matched.
func isTerminalQueryCSI(seq []byte) bool {
	body, final := seq[2:len(seq)-1], seq[len(seq)-1]
	var prefix byte
	if len(body) > 0 && body[0] >= '<' && body[0] <= '?' {
		prefix, body = body[0], body[1:]
	}
	params := body
	for len(params) > 0 && params[len(params)-1] >= 0x20 && params[len(params)-1] <= 0x2f {
		params = params[:len(params)-1]
	}
	intermediates := body[len(params):]
	switch final {
	case 'c': // device attributes
		return len(intermediates) == 0
	case 'n': // device status and cursor position; CSI > n sets key options
		return len(intermediates) == 0 && prefix != '>'
	case 'p': // DECRQM, mode state
		return string(intermediates) == "$"
	case 'q': // XTVERSION
		return prefix == '>' && len(intermediates) == 0
	case 'u': // keyboard protocol state
		return prefix == '?' && len(intermediates) == 0
	case 't': // window size and position reports
		if prefix != 0 || len(intermediates) != 0 {
			return false
		}
		first, _, _ := bytes.Cut(params, []byte(";"))
		switch string(first) {
		case "11", "13", "14", "15", "16", "18", "19", "20", "21":
			return true
		}
	}
	return false
}

// isTerminalQueryOSC reports whether an OSC payload asks for a colour or the
// clipboard: one of those numbers with a lone "?" as a value.
func isTerminalQueryOSC(payload []byte) bool {
	fields := bytes.Split(payload, []byte(";"))
	switch string(fields[0]) {
	case "4", "5", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "52":
	default:
		return false
	}
	for _, field := range fields[1:] {
		if string(field) == "?" {
			return true
		}
	}
	return false
}
