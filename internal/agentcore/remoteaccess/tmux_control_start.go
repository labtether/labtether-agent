package remoteaccess

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const (
	tmuxCommandTimeout = 5 * time.Second
	tmuxStartTimeout   = 8 * time.Second
	// The TERM a shell gets in a session started here. The browser's terminal
	// is an xterm, and with control mode the shell's bytes reach it unchanged.
	tmuxInnerTerm = "xterm-256color"
	// Marks a session started here, and so a shell that runs with that TERM.
	tmuxTermOption = "@labtether-term"
	// A new session starts with this in its first window. The shell is
	// started second, once the control client is attached and the history
	// length is set, so its first byte is already relayed. If the agent stops
	// in between, the placeholder ends on its own and takes the session along.
	tmuxPlaceholder = "exec sleep 60"
	// What a new terminal is sent before a new shell's output, in case the
	// Hub replayed an older session into it: leave the alternate screen and
	// switch off the modes a program may have left on. On a fresh terminal
	// none of it does anything.
	tmuxFreshTerminal = "\x18\x1b[?47l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?2004l" +
		"\x1b[?1l\x1b>\x1b[4l\x1b[?7h\x1b[?25h\x1b[0m"
)

var errTmuxControlUnsupported = errors.New("this tmux is older than 3.2")

// startTmuxControlTerminal creates the named tmux session or attaches to it,
// with a control-mode client instead of a terminal. It returns the terminal
// and the client process; ending that process detaches and leaves the session
// running. An error means nothing was left behind and the caller can use the
// PTY attach path.
func startTmuxControlTerminal(ctx context.Context, tmuxPath, session, dir string, cols, rows uint16, extraEnv []string) (*nativeTerminal, *exec.Cmd, error) {
	env := append(append(securityruntime.SanitizedChildEnv(), "TERM="+tmuxInnerTerm), extraEnv...)
	runIn := func(base context.Context, args ...string) (string, error) {
		runCtx, cancel := context.WithTimeout(base, tmuxCommandTimeout)
		defer cancel()
		cmd, err := securityruntime.NewCommandContext(runCtx, tmuxPath, args...)
		if err != nil {
			return "", err
		}
		cmd.Env, cmd.Dir = env, dir
		out, err := securityruntime.CaptureCombinedOutput(cmd, 64<<10)
		return strings.TrimSpace(string(out)), err
	}
	run := func(args ...string) (string, error) { return runIn(ctx, args...) }
	if version, err := run("-V"); err != nil || !tmuxSupportsControl(version) {
		return nil, nil, errTmuxControlUnsupported
	}
	if strings.ContainsAny(dir, "\r\n") {
		dir = ""
	}

	sessionID, placeholder, err := tmuxCreateSession(run, session, dir, cols, rows)
	if err != nil {
		return nil, nil, err
	}
	created := placeholder != ""
	// A start is often given up because its context was cancelled, and the
	// session made for it must still go: left behind, the next terminal of
	// this name would attach to the placeholder.
	abandon := func() {
		if created {
			_, _ = runIn(context.WithoutCancel(ctx), "kill-session", "-t", sessionID)
		}
	}

	cmd, err := securityruntime.NewCommandContext(ctx, tmuxPath, "-u", "-C", "attach-session", "-t", sessionID)
	if err != nil {
		abandon()
		return nil, nil, err
	}
	cmd.Env, cmd.Dir = env, dir
	terminal := newTmuxControlTerminal(int(cols), int(rows))
	terminal.session = sessionID
	client, err := startTmuxControlClient(cmd, terminal.notify, terminal.out.end)
	if err != nil {
		abandon()
		return nil, nil, err
	}
	terminal.client = client

	startCtx, cancel := context.WithTimeout(ctx, tmuxStartTimeout)
	defer cancel()
	if created {
		err = terminal.startShell(startCtx, dir, placeholder)
	} else {
		err = terminal.attachPane(startCtx)
	}
	if err != nil {
		client.kill()
		<-client.done
		abandon()
		return nil, nil, fmt.Errorf("tmux control mode: %w", err)
	}
	go terminal.manage()

	done := make(chan error, 1)
	go func() {
		<-client.done
		done <- nil
		close(done)
	}()
	return &nativeTerminal{
		input:       terminal,
		output:      terminal.out,
		done:        done,
		resize:      terminal.resize,
		outputChunk: tmuxOutputChunkBytes,
		// What is queued when the shell exits leaves at the paced rate.
		drainTimeout: tmuxOutputDrainTimeout,
	}, cmd, nil
}

// startTmuxControl tries the control-mode terminal. Nil means the caller
// attaches through a PTY.
func (tm *TerminalManager) startTmuxControl(ctx context.Context, tmuxPath string, req protocol.TerminalStartData, dir string, cols, rows uint16) (*nativeTerminal, *exec.Cmd) {
	native, cmd, err := startTmuxControlTerminal(ctx, tmuxPath, req.TmuxSession, dir, cols, rows, tm.tmuxEnv)
	if err == nil {
		return native, cmd
	}
	if !errors.Is(err, errTmuxControlUnsupported) && ctx.Err() == nil {
		log.Printf("terminal: session %s attaches to tmux through a PTY: %v", req.SessionID, err)
	}
	return nil, nil
}

// tmuxCreateSession starts the session detached with the placeholder window
// and returns its ID and that window. When the session exists already it
// returns the existing session's ID and no window.
func tmuxCreateSession(run func(...string) (string, error), session, dir string, cols, rows uint16) (id, placeholder string, err error) {
	args := []string{"new-session", "-d", "-P", "-F", "#{session_id} #{window_id}", "-s", session,
		"-x", strconv.Itoa(int(cols)), "-y", strconv.Itoa(int(rows))}
	if dir != "" {
		args = append(args, "-c", tmuxLiteralFormat(dir))
	}
	out, err := run(append(args, tmuxPlaceholder)...)
	if err == nil {
		fields := strings.Fields(out)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "$") || !strings.HasPrefix(fields[1], "@") {
			_, _ = run("kill-session", "-t", "="+session)
			return "", "", fmt.Errorf("unexpected tmux new-session output %q", out)
		}
		return fields[0], fields[1], nil
	}
	if !strings.Contains(out, "duplicate session") {
		return "", "", fmt.Errorf("tmux new-session: %s", firstNonEmpty(out, err.Error()))
	}
	list, err := run("list-sessions", "-F", "#{session_id} #{session_name}")
	if err != nil {
		return "", "", fmt.Errorf("tmux list-sessions: %s", firstNonEmpty(list, err.Error()))
	}
	for _, line := range strings.Split(list, "\n") {
		candidate, name, _ := strings.Cut(line, " ")
		if name == session || name == tmuxSanitizedSessionName(session) {
			return candidate, "", nil
		}
	}
	return "", "", fmt.Errorf("tmux session %q not found", session)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// startShell finishes a new session: options first, then the shell in a
// second window, then the placeholder goes. The shell's pane is live from the
// moment tmux creates it, so the terminal shows the shell's output from the
// first byte and needs no captured screen.
func (t *tmuxControlTerminal) startShell(ctx context.Context, dir, placeholder string) error {
	reply, err := t.client.call(ctx, "refresh-client -f pause-after="+tmuxPauseAfterSeconds+" ; "+
		tmuxResizeCommand(t.cols, t.rows)+" ; display-message -p '#{history-limit}'", 3)
	if err != nil {
		return err
	}
	options := "set-option status off ; set-option " + tmuxTermOption + " " + tmuxInnerTerm
	commands := 2
	// Raise the history length for this session only, and never lower one a
	// person configured.
	if limit, convErr := strconv.Atoi(reply.first(2)); convErr != nil || limit < tmuxHistoryLines {
		options = "set-option history-limit " + strconv.Itoa(tmuxHistoryLines) + " ; " + options
		commands = 3
	}
	if _, err := t.client.call(ctx, options, commands); err != nil {
		return err
	}
	window := "new-window -d -P -F '#{pane_id}' -e TERM=" + tmuxInnerTerm
	if dir != "" {
		window += " -c " + tmuxQuote(tmuxLiteralFormat(dir))
	}
	return t.callThen(ctx, window+" ; kill-window -t "+placeholder, 2, func(reply tmuxReply) error {
		pane := ""
		if len(reply.blocks) > 0 {
			pane = tmuxFirstPane(reply.blocks[0])
		}
		if pane == "" {
			return errors.New("tmux did not name the new pane")
		}
		t.out.addScreen([]byte(tmuxFreshTerminal))
		t.pane, t.live = pane, true
		t.mu.Lock()
		t.target, t.liveSince = pane, time.Now()
		t.mu.Unlock()
		return nil
	})
}

// attachPane joins a session that is already running and finds its first
// pane. The pane's history and screen are drawn into the new terminal by
// manage, as soon as the browser's size is known or a moment has passed.
func (t *tmuxControlTerminal) attachPane(ctx context.Context) error {
	if _, err := t.client.call(ctx, "refresh-client -f pause-after="+tmuxPauseAfterSeconds, 1); err != nil {
		return err
	}
	err := t.callThen(ctx, "list-panes -s -F '#{pane_id}'", 1, func(reply tmuxReply) error {
		pane := ""
		if len(reply.blocks) > 0 {
			pane = tmuxFirstPane(reply.blocks[0])
		}
		if pane == "" {
			return errors.New("tmux session has no pane")
		}
		t.pane = pane
		t.mu.Lock()
		t.target = pane
		t.held, t.firstSize, t.nudgeAfter = true, true, true
		t.heldAt = time.Now()
		t.mu.Unlock()
		return nil
	})
	t.signal()
	return err
}

// callThen sends one line and waits for then, which runs on the reader
// goroutine as soon as the reply is complete.
func (t *tmuxControlTerminal) callThen(ctx context.Context, line string, commands int, then func(tmuxReply) error) error {
	result := make(chan error, 1)
	err := t.client.send(line, commands, func(reply tmuxReply) {
		if err := reply.err(); err != nil {
			result <- err
			return
		}
		result <- then(reply)
	})
	if err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// tmuxFirstPane returns the first pane ID ("%3") among reply lines.
func tmuxFirstPane(lines [][]byte) string {
	for _, line := range lines {
		if len(line) < 2 || line[0] != '%' {
			continue
		}
		if _, err := strconv.Atoi(string(line[1:])); err == nil {
			return string(line)
		}
	}
	return ""
}
