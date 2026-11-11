package remoteaccess

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

const (
	// tmuxHistoryLines is the history a session started here keeps, and how
	// much of it a newly opened terminal is given.
	tmuxHistoryLines = 10000
	// tmuxSeedMaxBytes bounds one redrawn screen with its history. Older
	// lines are left out first.
	tmuxSeedMaxBytes = 8 << 20
	// tmuxSeedCommands is the number of commands in tmuxSeedCommand's line.
	tmuxSeedCommands = 7
)

// tmuxPaneFormat asks for everything needed to put a new terminal into the
// state the pane is in. cmd is last because a program name may hold spaces.
const tmuxPaneFormat = "w=#{pane_width} h=#{pane_height} cx=#{cursor_x} cy=#{cursor_y} hist=#{history_size} " +
	"alt=#{alternate_on} sx=#{alternate_saved_x} sy=#{alternate_saved_y} cur=#{cursor_flag} ins=#{insert_flag} " +
	"kc=#{keypad_cursor_flag} kp=#{keypad_flag} wrap=#{wrap_flag} m0=#{mouse_standard_flag} m2=#{mouse_button_flag} " +
	"m3=#{mouse_all_flag} msgr=#{mouse_sgr_flag} mutf=#{mouse_utf8_flag} top=#{scroll_region_upper} " +
	"bot=#{scroll_region_lower} bp=#{bracket_paste_flag} term=#{" + tmuxTermOption + "} cmd=#{pane_current_command}"

// tmuxSeedCommand is one line, so tmux runs it without reading pane output in
// between: the captured screen and the output that follows it line up exactly,
// with nothing lost and nothing twice.
//
// It resumes the pane if tmux paused it, sets the size, then reads the state
// and four views: history with the screen (wrapped lines joined), the screen
// row by row, the history alone, and the screen under a full-screen program.
func tmuxSeedCommand(pane string, cols, rows int) string {
	history := strconv.Itoa(tmuxHistoryLines)
	return strings.Join([]string{
		"refresh-client -A " + tmuxQuote(pane+":continue"),
		fmt.Sprintf("refresh-client -C %dx%d", cols, rows),
		"display-message -p -t " + pane + " " + tmuxQuote(tmuxPaneFormat),
		"capture-pane -p -e -J -t " + pane + " -S -" + history + " -E -",
		"capture-pane -p -e -t " + pane + " -S 0 -E -",
		"capture-pane -p -e -J -t " + pane + " -S -" + history + " -E -1",
		"capture-pane -p -e -J -a -q -t " + pane + " -S - -E -",
	}, " ; ")
}

type tmuxPaneState struct {
	width, height    int
	cursorX, cursorY int
	history          int
	alternate        bool
	savedX, savedY   int // cursor under the full-screen program; -1 unknown
	cursorShown      bool
	insert           bool
	keypadCursor     bool
	keypad           bool
	wrap             bool
	mouseStandard    bool
	mouseButton      bool
	mouseAll         bool
	mouseSGR         bool
	mouseUTF8        bool
	regionTop        int
	regionBottom     int
	bracketPaste     string // "1", "0", or "" when this tmux cannot tell
	term             string // set on sessions started here: the TERM inside
	command          string
}

func parseTmuxPaneState(line string) (tmuxPaneState, error) {
	state := tmuxPaneState{savedX: -1, savedY: -1}
	head, command, _ := strings.Cut(line, " cmd=")
	state.command = command
	values := map[string]string{}
	for _, field := range strings.Fields(head) {
		key, value, _ := strings.Cut(field, "=")
		values[key] = value
	}
	number := func(key string) int {
		n, err := strconv.ParseUint(values[key], 10, 31)
		if err != nil {
			return -1
		}
		return int(n)
	}
	state.width, state.height = number("w"), number("h")
	state.cursorX, state.cursorY = number("cx"), number("cy")
	state.history = number("hist")
	if state.width <= 0 || state.height <= 0 || state.cursorX < 0 || state.cursorY < 0 || state.history < 0 {
		return state, fmt.Errorf("unreadable tmux pane state %q", line)
	}
	state.savedX, state.savedY = number("sx"), number("sy")
	state.regionTop, state.regionBottom = number("top"), number("bot")
	on := func(key string) bool { return values[key] == "1" }
	state.alternate = on("alt")
	state.cursorShown = values["cur"] != "0"
	state.insert, state.keypadCursor, state.keypad = on("ins"), on("kc"), on("kp")
	state.wrap = values["wrap"] != "0"
	state.mouseStandard, state.mouseButton, state.mouseAll = on("m0"), on("m2"), on("m3")
	state.mouseSGR, state.mouseUTF8 = on("msgr"), on("mutf")
	state.bracketPaste, state.term = values["bp"], values["term"]
	return state, nil
}

// pasteBracketed says whether the program in the pane asked for bracketed
// paste. tmux 3.7 reports it. Older tmux does not, so there the answer comes
// from what runs in the pane: a shell at its prompt that turns the mode on.
// Without it a pasted block of lines would run line by line after a
// re-attach, until the shell printed its next prompt.
func (s tmuxPaneState) pasteBracketed() bool {
	if s.bracketPaste != "" {
		return s.bracketPaste == "1"
	}
	if s.alternate {
		return false
	}
	switch strings.TrimPrefix(s.command, "-") {
	case "zsh", "fish":
		return true
	case "bash":
		// macOS ships bash 3.2, which has no bracketed paste.
		return runtime.GOOS != "darwin"
	}
	return false
}

// tmuxSeedViews are the four captures of tmuxSeedCommand.
type tmuxSeedViews struct {
	flow    [][]byte // history and screen, wrapped lines joined
	rows    [][]byte // the screen, one entry per row
	history [][]byte // history alone, wrapped lines joined
	saved   [][]byte // the screen under a full-screen program
}

// seedStart cancels a half-written escape sequence, resets the terminal and
// drops its scroll-back: whatever the terminal showed before, it now shows
// what follows.
const seedStart = "\x18\x1bc\x1b[3J"

// renderTmuxSeed writes what a terminal of cols by rows needs to look like
// the pane: history above, the screen, the cursor, and the modes the program
// set. Under a full-screen program the normal screen is rebuilt first, so it
// is there when the program exits.
func renderTmuxSeed(state tmuxPaneState, views tmuxSeedViews, cols, rows int) []byte {
	out := []byte(seedStart)
	historyRows := min(state.history, tmuxHistoryLines)
	// Row of the pane's row 0 in the terminal, once everything is written.
	top := historyRows - max(0, historyRows+state.height-rows)
	place := func(x, y int) []byte {
		row := min(max(top+y, 0), rows-1) + 1
		col := min(max(x, 0), cols-1) + 1
		return fmt.Appendf(nil, "\x1b[%d;%dH", row, col)
	}
	if !state.alternate {
		out = appendSeedFlow(out, views.flow)
	} else {
		normal := views.saved
		if state.history > 0 {
			normal = append(append([][]byte{}, views.history...), views.saved...)
		}
		out = appendSeedFlow(out, normal)
		if state.savedX >= 0 && state.savedY >= 0 && state.savedY < state.height {
			out = append(out, place(state.savedX, state.savedY)...)
		}
		// Switch screens, and make G1 the line-drawing set: tmux marks drawn
		// lines with shift-out and shift-in.
		out = append(out, "\x1b[?1049h\x1b)0"...)
		top = 0
		for y, row := range views.rows {
			if y >= rows {
				break
			}
			out = fmt.Appendf(out, "\x1b[%d;1H", y+1)
			out = append(out, row...)
		}
		out = append(out, "\x0f"...)
	}
	out = append(out, "\x1b[0m"...)
	if state.regionTop >= 0 && state.regionBottom > state.regionTop &&
		(state.regionTop > 0 || state.regionBottom < state.height-1) {
		out = fmt.Appendf(out, "\x1b[%d;%dr", state.regionTop+1, state.regionBottom+1)
	}
	out = append(out, place(state.cursorX, state.cursorY)...)
	return append(out, state.modes()...)
}

// modes are the settings the program switched on, in the terminal's own words.
func (s tmuxPaneState) modes() string {
	var b strings.Builder
	add := func(on bool, sequence string) {
		if on {
			b.WriteString(sequence)
		}
	}
	add(!s.cursorShown, "\x1b[?25l")
	add(s.insert, "\x1b[4h")
	add(s.keypadCursor, "\x1b[?1h")
	add(s.keypad, "\x1b=")
	add(!s.wrap, "\x1b[?7l")
	add(s.mouseStandard, "\x1b[?1000h")
	add(s.mouseButton, "\x1b[?1002h")
	add(s.mouseAll, "\x1b[?1003h")
	add(s.mouseUTF8, "\x1b[?1005h")
	add(s.mouseSGR, "\x1b[?1006h")
	add(s.pasteBracketed(), "\x1b[?2004h")
	return b.String()
}

// appendSeedFlow writes lines one below the other, oldest first, the way the
// shell printed them. Lines longer than the terminal wrap there as they did
// in the pane, so the terminal can re-wrap them on resize and copy them whole.
//
// tmux carries a background colour from the end of one captured line to the
// start of the next. A terminal fills a new line with the current background,
// so the colour is switched off across the line break and back on after it.
func appendSeedFlow(out []byte, lines [][]byte) []byte {
	size := 0
	first := len(lines)
	for first > 0 && size+len(lines[first-1])+2 <= tmuxSeedMaxBytes {
		first--
		size += len(lines[first]) + 2
	}
	var background []byte
	for i, line := range lines {
		if i >= first {
			if i > first {
				if background != nil {
					out = append(out, "\x1b[49m"...)
				}
				out = append(out, '\r', '\n')
			}
			out = append(out, background...)
			out = append(out, line...)
		}
		background = seedBackground(background, line)
	}
	return out
}

// seedBackground returns the background colour sequence in force after line,
// or nil for the default background.
func seedBackground(current, line []byte) []byte {
	for {
		start := bytes.Index(line, []byte("\x1b["))
		if start < 0 {
			return current
		}
		line = line[start+2:]
		end := 0
		for end < len(line) && (line[end] < 0x40 || line[end] > 0x7e) {
			end++
		}
		if end == len(line) {
			return current
		}
		if line[end] == 'm' {
			current = seedBackgroundAfterSGR(current, line[:end])
		}
		line = line[end+1:]
	}
}

func seedBackgroundAfterSGR(current, params []byte) []byte {
	if len(params) == 0 {
		return nil
	}
	fields := bytes.Split(params, []byte(";"))
	for i := 0; i < len(fields); i++ {
		code, _, _ := bytes.Cut(fields[i], []byte(":"))
		n, err := strconv.Atoi(string(code))
		if err != nil {
			continue
		}
		// 38, 48 and 58 take their colour in the fields that follow, unless
		// it came in the same field after a colon.
		extended := 0
		if (n == 38 || n == 48 || n == 58) && len(code) == len(fields[i]) && i+1 < len(fields) {
			switch string(fields[i+1]) {
			case "5":
				extended = 2
			case "2":
				extended = 4
			}
			extended = min(extended, len(fields)-1-i)
		}
		switch {
		case n == 0 || n == 49:
			current = nil
		case (n >= 40 && n <= 47) || (n >= 100 && n <= 107) || n == 48:
			current = append([]byte("\x1b["), bytes.Join(fields[i:i+1+extended], []byte(";"))...)
			current = append(current, 'm')
		}
		i += extended
	}
	return current
}

// tmuxSeedViewsFromReply picks the captures out of the reply to
// tmuxSeedCommand, and the state line before them.
func tmuxSeedViewsFromReply(reply tmuxReply) (tmuxPaneState, tmuxSeedViews, error) {
	if err := reply.err(); err != nil {
		return tmuxPaneState{}, tmuxSeedViews{}, err
	}
	if len(reply.blocks) != tmuxSeedCommands {
		return tmuxPaneState{}, tmuxSeedViews{}, fmt.Errorf("tmux answered %d of %d commands", len(reply.blocks), tmuxSeedCommands)
	}
	state, err := parseTmuxPaneState(reply.first(2))
	if err != nil {
		return state, tmuxSeedViews{}, err
	}
	return state, tmuxSeedViews{
		flow:    reply.blocks[3],
		rows:    reply.blocks[4],
		history: reply.blocks[5],
		saved:   reply.blocks[6],
	}, nil
}
