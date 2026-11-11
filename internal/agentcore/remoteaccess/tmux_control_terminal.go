package remoteaccess

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

const (
	// tmux pauses a pane for this client when its output has waited this
	// long, and drops what it kept. That bounds the server's memory when a
	// second, ordinary client keeps the pane running at full speed.
	tmuxPauseAfterSeconds = "5"
	// How long skipped output stays skipped before the screen is redrawn.
	// The wait doubles while a program keeps flooding, up to the maximum.
	tmuxHoldMin = 250 * time.Millisecond
	tmuxHoldMax = 2 * time.Second
	// A key press ends the wait early, so Ctrl+C shows its effect at once.
	tmuxHoldAfterKey = 100 * time.Millisecond
	tmuxPanesDelay   = 150 * time.Millisecond
)

// Home and End as the browser's terminal sends them, and as a program started
// under tmux's own TERM expects them. Sessions started here run their shell
// with TERM=xterm-256color and need no translation; sessions from the PTY
// attach path keep tmux's TERM, where tmux used to translate these two keys.
var tmuxOwnTermKeys = map[string]string{
	"\x1b[H": "\x1b[1~", "\x1bOH": "\x1b[1~",
	"\x1b[F": "\x1b[4~", "\x1bOF": "\x1b[4~",
}

// tmuxControlTerminal relays one tmux pane to the Hub through a control-mode
// client. The browser receives the bytes the shell wrote, not tmux's drawing
// of them, so its own scroll-back, search and copy work as on a plain
// terminal. The tmux session keeps the shell alive between connections.
//
// When output arrives faster than it can be sent, the terminal does not keep
// it and does not slow the program: it skips ahead. tmux is told to stop
// sending, and a moment later the screen and its history are read back from
// tmux and sent in place of what was skipped.
type tmuxControlTerminal struct {
	client *tmuxControlClient
	out    *tmuxOutputQueue

	// Reader goroutine only.
	pane    string // the pane relayed; other panes of the session are ignored
	live    bool   // pane output is being forwarded
	filter  terminalQueryFilter
	decoded []byte
	clean   []byte

	mu         sync.Mutex
	target     string // pane typed input goes to
	cols, rows int
	ownTerm    bool // the pane's programs expect tmux's key codes
	held       bool // output is skipped until the screen is redrawn
	heldAt     time.Time
	holdDelay  time.Duration
	keyPressed bool // a key arrived while held
	seedNow    bool // redraw without waiting: the browser's size is known
	firstSize  bool // attached, and the browser has not sent its size yet
	seeding    bool // the redraw has been asked for
	liveSince  time.Time
	nudgeAfter bool // make a full-screen program repaint after the next redraw
	pauseDue   bool
	resizeDue  bool
	nudgeDue   bool
	panesDue   bool
	panesAt    time.Time

	wake chan struct{}
}

func newTmuxControlTerminal(cols, rows int) *tmuxControlTerminal {
	return &tmuxControlTerminal{
		out:       newTmuxOutputQueue(),
		cols:      cols,
		rows:      rows,
		holdDelay: tmuxHoldMin,
		wake:      make(chan struct{}, 1),
	}
}

func (t *tmuxControlTerminal) signal() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// notify handles one notification line. It runs on the reader goroutine and
// never waits: output that does not fit is skipped, not queued.
func (t *tmuxControlTerminal) notify(line []byte) {
	if pane, data, ok := tmuxOutputLine(line); ok {
		if !t.live || string(pane) != t.pane {
			return
		}
		t.decoded = appendTmuxUnescaped(t.decoded[:0], data)
		t.clean = t.filter.apply(t.clean[:0], t.decoded)
		if len(t.clean) > 0 && !t.out.addLive(t.clean) {
			t.out.discard()
			t.hold(true)
		}
		return
	}
	word, rest, _ := bytes.Cut(line, []byte(" "))
	switch string(word) {
	case "%pause":
		if t.live && string(rest) == t.pane {
			t.hold(false)
		}
	case "%layout-change", "%window-close", "%unlinked-window-close", "%window-pane-changed":
		t.mu.Lock()
		if !t.panesDue {
			t.panesDue, t.panesAt = true, time.Now().Add(tmuxPanesDelay)
		}
		t.mu.Unlock()
		t.signal()
	}
}

// hold stops forwarding until the screen has been redrawn from tmux. Reader
// goroutine only.
func (t *tmuxControlTerminal) hold(pause bool) {
	t.live = false
	t.filter.reset()
	now := time.Now()
	t.mu.Lock()
	if !t.held {
		// A program that fills the queue again right after a redraw is
		// flooding: redraw less often.
		if now.Sub(t.liveSince) < tmuxHoldMax {
			t.holdDelay = min(t.holdDelay*2, tmuxHoldMax)
		} else {
			t.holdDelay = tmuxHoldMin
		}
		t.held, t.heldAt, t.keyPressed = true, now, false
	}
	t.pauseDue = t.pauseDue || pause
	t.mu.Unlock()
	t.signal()
}

// seeded receives the reply to tmuxSeedCommand on the reader goroutine. The
// lines read after it are the pane's output from exactly where the captured
// screen ends.
func (t *tmuxControlTerminal) seeded(reply tmuxReply, cols, rows int) error {
	state, views, err := tmuxSeedViewsFromReply(reply)
	if err != nil {
		// The pane may be gone: look for another, and try again later.
		t.mu.Lock()
		t.seeding = false
		t.heldAt = time.Now()
		t.holdDelay = min(t.holdDelay*2, tmuxHoldMax)
		t.panesDue, t.panesAt = true, t.heldAt
		t.mu.Unlock()
		t.signal()
		return err
	}
	t.mu.Lock()
	if cols != t.cols || rows != t.rows {
		// The browser changed size while tmux answered. A screen laid out for
		// the old size would put the cursor on the wrong row: draw again.
		t.seeding, t.held, t.seedNow, t.heldAt = false, true, true, time.Now()
		t.mu.Unlock()
		t.signal()
		return nil
	}
	t.mu.Unlock()
	t.out.addScreen(renderTmuxSeed(state, views, cols, rows))
	t.filter.reset()
	t.live = true
	t.mu.Lock()
	t.seeding, t.held, t.seedNow = false, false, false
	t.liveSince = time.Now()
	t.ownTerm = state.term == ""
	t.nudgeDue = t.nudgeAfter && state.alternate
	t.nudgeAfter = false
	t.mu.Unlock()
	t.signal()
	return nil
}

// panesListed keeps the terminal on a pane that exists. A person who attaches
// with their own tmux client can split the window or close the first pane.
func (t *tmuxControlTerminal) panesListed(reply tmuxReply) {
	if reply.err() != nil || len(reply.blocks) == 0 {
		return
	}
	first := ""
	for _, line := range reply.blocks[0] {
		if string(line) == t.pane {
			return
		}
		if first == "" && len(line) > 1 && line[0] == '%' {
			first = string(line)
		}
	}
	if first == "" {
		return
	}
	t.pane = first
	t.mu.Lock()
	t.target = first
	t.mu.Unlock()
	t.hold(false)
}

// manage sends the commands that notify, Write and resize ask for. They are
// sent from here so that none of those ever waits on tmux.
func (t *tmuxControlTerminal) manage() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-t.client.done:
			return
		case <-t.wake:
		case <-t.out.drained:
		case <-timer.C:
		}
		if next := t.work(time.Now()); next > 0 {
			timer.Reset(next)
		}
	}
}

// work does what is due and returns how long until something else is.
func (t *tmuxControlTerminal) work(now time.Time) time.Duration {
	var next time.Duration
	later := func(at time.Time) bool {
		if wait := at.Sub(now); wait > 0 {
			if next == 0 || wait < next {
				next = wait
			}
			return true
		}
		return false
	}
	t.mu.Lock()
	pane, cols, rows := t.target, t.cols, t.rows
	pause, resize, nudge := t.pauseDue, t.resizeDue, t.nudgeDue
	t.pauseDue, t.resizeDue, t.nudgeDue = false, false, false
	panes := t.panesDue && !later(t.panesAt)
	if panes {
		t.panesDue = false
	}
	seed := false
	if t.held && !t.seeding {
		delay := t.holdDelay
		if t.keyPressed {
			delay = min(delay, tmuxHoldAfterKey)
		}
		// Wait for an earlier redraw to leave first; a second one behind it
		// would only repeat it.
		if t.seedNow || (!later(t.heldAt.Add(delay)) && t.out.pending() == 0) {
			seed, t.seeding, t.seedNow = true, true, false
		}
	}
	t.mu.Unlock()

	if pause {
		_ = t.client.send("refresh-client -A "+tmuxQuote(pane+":pause"), 1, nil)
	}
	if resize && !seed {
		_ = t.client.send(tmuxResizeCommand(cols, rows), 1, nil)
	}
	if panes {
		_ = t.client.send("list-panes -s -F '#{pane_id}'", 1, t.panesListed)
	}
	if seed {
		_ = t.client.send(tmuxSeedCommand(pane, cols, rows), tmuxSeedCommands, func(reply tmuxReply) {
			_ = t.seeded(reply, cols, rows)
		})
	}
	if nudge {
		// tmux sends a program two size changes when the size ends where it
		// began, which is what makes it repaint.
		if rows > 2 {
			_ = t.client.send(tmuxResizeCommand(cols, rows-1), 1, nil)
		} else {
			_ = t.client.send(tmuxResizeCommand(cols+1, rows), 1, nil)
		}
		_ = t.client.send(tmuxResizeCommand(cols, rows), 1, nil)
	}
	return next
}

func tmuxResizeCommand(cols, rows int) string {
	return fmt.Sprintf("refresh-client -C %dx%d", cols, rows)
}

// resize follows the browser's terminal size.
//
// The Hub starts every terminal at a default size; the browser's real size
// comes in a resize right after. For a session that was already running, the
// screen is drawn for that real size: once when it arrives in time, again
// when it arrives after the first drawing.
func (t *tmuxControlTerminal) resize(cols, rows uint16) {
	t.mu.Lock()
	changed := t.cols != int(cols) || t.rows != int(rows)
	t.cols, t.rows = int(cols), int(rows)
	switch {
	case !t.firstSize:
		t.resizeDue = true
	case t.held || changed:
		if !t.held {
			t.held, t.heldAt = true, time.Now()
		}
		t.seedNow = true
	}
	t.firstSize = false
	t.mu.Unlock()
	t.signal()
}

// Write sends typed bytes to the pane.
func (t *tmuxControlTerminal) Write(data []byte) (int, error) {
	t.mu.Lock()
	pane, ownTerm := t.target, t.ownTerm
	wake := t.held && !t.keyPressed
	if wake {
		t.keyPressed = true
	}
	t.mu.Unlock()
	if wake {
		t.signal()
	}
	keys := data
	if ownTerm {
		if translated, ok := tmuxOwnTermKeys[string(data)]; ok {
			keys = []byte(translated)
		}
	}
	for _, line := range tmuxSendKeysLines(pane, keys) {
		if err := t.client.send(line, 1, nil); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

// Close detaches: the control client ends and the session keeps running.
func (t *tmuxControlTerminal) Close() error {
	t.client.kill()
	return nil
}
