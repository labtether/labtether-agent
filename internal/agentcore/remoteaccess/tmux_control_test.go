//go:build !windows

package remoteaccess

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// The fault this rebuild removes: tmux drew the shell on the alternate
// screen, so the browser had no scroll-back, and a redraw-based relay dropped
// lines under fast output. Every printed line must arrive, in order, as the
// shell wrote it.
func TestTmuxControlRelaysEveryLineOnTheNormalScreen(t *testing.T) {
	h := newTmuxHarness(t)
	id := h.open("lt-lines", 100, 30)
	h.ready(id)
	h.typeLine(id, "seq 1 5000; echo lines-$((5*5))-done")
	out := h.waitOutput(id, "lines-25-done", 30*time.Second)
	if bytes.Contains(out, []byte("\x1b[?1049h")) || bytes.Contains(out, []byte("\x1b[?47h")) {
		t.Fatal("the terminal was switched to the alternate screen")
	}
	next, numbers := 1, 0
	for _, line := range plainLines(out) {
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > 5000 {
			continue
		}
		numbers++
		if n == next {
			next++
		}
	}
	if next != 5001 || numbers != 5000 {
		t.Fatalf("lines 1..5000: in order up to %d, %d number lines in all", next-1, numbers)
	}
}

// Output and input pass through tmux's octal escaping and send-keys -H. A
// wrong escape, a dropped byte or a reordered paste chunk corrupts what a
// person sees or types.
func TestTmuxControlPassesEveryByteBothWays(t *testing.T) {
	h := newTmuxHarness(t)
	id := h.open("lt-bytes", 100, 30)
	h.ready(id)
	shell := h.tmux("display-message", "-p", "-t", "=lt-bytes:", "#{pane_current_command}")

	all := make([]byte, 0, 768)
	for i := 0; i < 768; i++ {
		all = append(all, byte(i))
	}
	if err := os.WriteFile(filepath.Join(h.home, "all.bin"), all, 0o600); err != nil {
		t.Fatal(err)
	}
	h.typeLine(id, "stty raw -echo; printf 'ST''ART'; cat all.bin; printf 'FIN''ISH'; stty sane")
	out := h.waitOutput(id, "FINISH", 15*time.Second)
	printed := out[bytes.Index(out, []byte("START"))+5 : bytes.LastIndex(out, []byte("FINISH"))]
	if !bytes.Equal(printed, all) {
		t.Fatalf("printed bytes changed on the way: got %d bytes, want %d", len(printed), len(all))
	}

	paste := bytes.Repeat([]byte("line one of a pasted block; echo not-run\nsecond line: grüße 日本語\n"), 100)
	typed := append([]byte{}, all[:256]...)
	typed = append(typed, "grüße 日本語 😀 \x1b[A\x1b[1;5C\x1b[<0;10;5M"...)
	typed = append(typed, "\x1b[200~"+string(paste)+"\x1b[201~"...)
	h.typeLine(id, fmt.Sprintf("stty raw -echo; head -c %d > typed.bin; stty sane; echo typed-$((2*3))-saved", len(typed)))
	h.waitTmux("lt-bytes", "#{pane_current_command}", "head", 10*time.Second)
	h.typeBytes(id, typed[:300])
	h.typeBytes(id, typed[300:])
	h.waitOutput(id, "typed-6-saved", 20*time.Second)
	got, err := os.ReadFile(filepath.Join(h.home, "typed.bin"))
	if err != nil || !bytes.Equal(got, typed) {
		t.Fatalf("typed bytes changed on the way: got %d bytes, want %d (%v)", len(got), len(typed), err)
	}

	h.typeLine(id, "sleep 600")
	h.waitTmux("lt-bytes", "#{pane_current_command}", "sleep", 10*time.Second)
	h.typeBytes(id, []byte{0x03})
	h.waitTmux("lt-bytes", "#{pane_current_command}", shell, 10*time.Second)
}

// A resize from the browser must reach the program, or full-screen tools and
// line wrapping use the wrong size.
func TestTmuxControlResizeReachesTheShell(t *testing.T) {
	h := newTmuxHarness(t)
	id := h.open("lt-size", 100, 30)
	h.ready(id)
	h.resize(id, 91, 27)
	deadline := time.Now().Add(10 * time.Second)
	for !bytes.Contains(h.seen(id), []byte("\r\n27 91\r\n")) {
		if time.Now().After(deadline) {
			t.Fatal("stty size never reported 27 91")
		}
		h.typeLine(id, "stty size")
		time.Sleep(300 * time.Millisecond)
	}
}

// Closing the tab detaches; opening the session again must show the earlier
// output once, and continue exactly where the captured screen ends, even
// while the shell keeps printing. A gap or a repeat here is a lost or doubled
// line on a person's screen.
func TestTmuxControlReattachContinuesWithoutGapOrRepeat(t *testing.T) {
	h := newTmuxHarness(t)
	first := h.open("lt-again", 80, 24)
	h.ready(first)
	h.typeLine(first, "i=0; while [ $i -lt 1500 ]; do i=$((i+1)); echo n$i; sleep 0.002; done; echo loop-$((3*3))-over")
	h.waitOutput(first, "n200\r", 30*time.Second)
	h.detach(first)
	if out := h.tmux("has-session", "-t", "=lt-again"); out != "" {
		t.Fatalf("session ended with its terminal: %s", out)
	}

	counted := func(out []byte) int {
		t.Helper()
		last := 0
		for _, line := range plainLines(out) {
			if !strings.HasPrefix(line, "n") {
				continue
			}
			n, err := strconv.Atoi(line[1:])
			if err != nil {
				continue
			}
			if n != last+1 {
				t.Fatalf("after n%d came n%d", last, n)
			}
			last = n
		}
		return last
	}

	second := h.open("lt-again", 80, 24)
	out := h.waitOutput(second, "n700\r", 30*time.Second)
	if !bytes.HasPrefix(out, []byte(seedStart)) {
		t.Fatalf("a re-opened terminal must start from a reset; got %q", out[:min(len(out), 40)])
	}
	h.detach(second)
	if reached := counted(h.seen(second)); reached < 700 {
		t.Fatalf("second terminal reached n%d", reached)
	}

	// A third terminal with another size, as from a different browser window.
	third := h.open("lt-again", 100, 30)
	out = h.waitOutput(third, "loop-9-over", 60*time.Second)
	if reached := counted(out); reached != 1500 {
		t.Fatalf("third terminal reached n%d, want n1500", reached)
	}
}

// The console opens every terminal at the Hub's default size and sends its
// real size a moment later. A screen drawn for the default size puts the
// cursor on the wrong row of the real terminal, and the shell's next prompt
// redraw then erases lines there (seen in the lab: the last lines of a
// re-opened session were gone).
func TestTmuxControlDrawsForTheBrowsersRealSize(t *testing.T) {
	h := newTmuxHarness(t)
	first := h.open("lt-real", 100, 30)
	h.ready(first)
	h.typeLine(first, `seq 1 80; printf 'long:%0200d:end\n' 7`)
	h.waitOutput(first, ":end\r", 15*time.Second)
	h.detach(first)

	drawnFor := func(id string, redraws int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for bytes.Count(h.seen(id), []byte(seedStart)) < redraws {
			if time.Now().After(deadline) {
				t.Fatalf("screen drawn %d times, want %d", bytes.Count(h.seen(id), []byte(seedStart)), redraws)
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(600 * time.Millisecond)
		out := h.seen(id)
		if got := bytes.Count(out, []byte(seedStart)); got != redraws {
			t.Fatalf("screen drawn %d times, want %d", got, redraws)
		}
		h.waitTmux("lt-real", "#{pane_width}x#{pane_height}", "92x44", 5*time.Second)
		var x, y int
		if _, err := fmt.Sscanf(h.tmux("display-message", "-p", "-t", "=lt-real:", "#{cursor_x} #{cursor_y}"), "%d %d", &x, &y); err != nil {
			t.Fatal(err)
		}
		last := out[bytes.LastIndex(out, []byte(seedStart)):]
		if want := fmt.Sprintf("\x1b[%d;%dH", y+1, x+1); !bytes.Contains(last, []byte(want)) {
			t.Fatalf("cursor not placed at %q for a 92x44 terminal; screen ends %q", want, last[max(0, len(last)-80):])
		}
	}

	// The real size arrives right after the start, as it does from the console.
	second := h.open("lt-real", 160, 40)
	h.resize(second, 92, 44)
	drawnFor(second, 1)
	h.detach(second)

	// It arrives after the screen was drawn for the default size.
	third := h.open("lt-real", 160, 40)
	h.waitOutput(third, seedStart, 10*time.Second)
	h.resize(third, 92, 44)
	drawnFor(third, 2)
}

// A full-screen program must be on screen again after a re-attach, with the
// cursor and the modes it set, and must be asked to repaint.
func TestTmuxControlRedrawsFullScreenProgram(t *testing.T) {
	h := newTmuxHarness(t)
	first := h.open("lt-full", 80, 24)
	h.ready(first)
	// One process group for the program and its sleep, as a full-screen
	// program has: the size change signal goes to the foreground group.
	h.typeLine(first, `sh -c 'printf "\033[?1049h\033[2J\033[?1000h\033[?1006h\033[?1h\033[5;10HFULLSCREEN"; trap "printf RE\"\"PAINT" WINCH; while :; do sleep 0.1; done'`)
	h.waitTmux("lt-full", "#{alternate_on}#{mouse_sgr_flag}#{cursor_x}", "1119", 15*time.Second)
	h.detach(first)

	second := h.open("lt-full", 80, 24)
	out := h.waitOutput(second, "REPAINT", 15*time.Second)
	screen := out[:bytes.Index(out, []byte("REPAINT"))]
	normal := bytes.Index(screen, []byte("shell-2-up"))
	alternate := bytes.Index(screen, []byte("\x1b[?1049h"))
	if !bytes.HasPrefix(screen, []byte(seedStart)) || normal < 0 || alternate < normal {
		t.Fatalf("normal screen and history must be rebuilt before the full-screen one (normal %d, switch %d)", normal, alternate)
	}
	for _, want := range []string{"\x1b[5;1H         FULLSCREEN", "\x1b[5;20H", "\x1b[?1000h", "\x1b[?1006h", "\x1b[?1h"} {
		if !bytes.Contains(screen[alternate:], []byte(want)) {
			t.Fatalf("full-screen redraw lacks %q", want)
		}
	}
	h.typeBytes(second, []byte{0x03})
	h.typeLine(second, `printf '\033[?1049l\033[?1000l\033[?1006l\033[?1l'; echo back-$((8*8))-in-shell`)
	h.waitOutput(second, "back-64-in-shell", 15*time.Second)
}

// A program that prints without end must not make the agent, the Hub's queue
// or tmux hold more and more, and Ctrl+C must still stop it.
func TestTmuxControlFloodStaysBoundedAndStops(t *testing.T) {
	h := newTmuxHarness(t)
	id := h.open("lt-flood", 100, 30)
	h.ready(id)
	shell := h.tmux("display-message", "-p", "-t", "=lt-flood:", "#{pane_current_command}")
	server := h.tmux("display-message", "-p", "-t", "=lt-flood:", "#{pid}")
	rss := func() int {
		out, _ := exec.Command("ps", "-o", "rss=", "-p", server).Output()
		kb, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return kb
	}
	before := rss()
	h.typeLine(id, "yes 0123456789012345678901234567890123456789")
	time.Sleep(4 * time.Second)
	grown, sent := rss()-before, len(h.seen(id))
	h.typeBytes(id, []byte{0x03})
	h.waitTmux("lt-flood", "#{pane_current_command}", shell, 10*time.Second)
	h.typeLine(id, "echo flood-$((7*7))-stopped")
	h.waitOutput(id, "flood-49-stopped", 15*time.Second)

	// Four seconds at 2 MiB a second plus the opening burst, with room for
	// the redrawn screens.
	if limit := 16 << 20; sent > limit {
		t.Fatalf("%d bytes were sent in four seconds, more than %d", sent, limit)
	}
	if grown > 64<<10 {
		t.Fatalf("the tmux server grew by %d kB during the flood", grown)
	}
}

// The session is what survives a dropped connection or an agent restart. It
// must outlive its client, and end when the shell does or when it is killed.
func TestTmuxControlSessionOutlivesClientAndEndsWithShell(t *testing.T) {
	h := newTmuxHarness(t)
	first := h.open("lt-keep", 80, 24)
	h.ready(first)
	h.typeLine(first, "kept=$((11*11))")
	client, err := strconv.Atoi(h.tmux("list-clients", "-t", "=lt-keep", "-F", "#{client_pid}"))
	if err != nil {
		t.Fatalf("no single control client: %v", err)
	}
	if err := syscall.Kill(client, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	h.waitClosed(first)
	if out := h.tmux("has-session", "-t", "=lt-keep"); out != "" {
		t.Fatalf("session ended with its client: %s", out)
	}

	second := h.open("lt-keep", 80, 24)
	h.typeLine(second, "echo kept-$kept-still")
	h.waitOutput(second, "kept-121-still", 15*time.Second)
	h.typeLine(second, "exit")
	if reason := h.waitClosed(second); reason != "shell exited" {
		t.Fatalf("close reason %q, want %q", reason, "shell exited")
	}
	if out := h.tmux("has-session", "-t", "=lt-keep"); out == "" {
		t.Fatal("session still runs after its shell exited")
	}

	third := h.open("lt-kill", 80, 24)
	h.ready(third)
	h.tmux("kill-session", "-t", "=lt-kill")
	h.waitClosed(third)
}

// Sessions that an older agent started through a PTY keep running across an
// agent update. They must open in control mode with their screen, and Home
// must still be the key their programs know.
func TestTmuxControlOpensSessionFromPTYPath(t *testing.T) {
	h := newTmuxHarness(t)
	old := exec.Command(h.tmuxPath, tmuxStartArgs("lt-old", h.home)...)
	old.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + h.home, "TERM=xterm-256color"}, h.env...)
	ptmx, err := pty.StartWithSize(old, &pty.Winsize{Cols: 100, Rows: 30})
	if err != nil {
		t.Fatalf("start tmux: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, readErr := ptmx.Read(buf); readErr != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(h.tmux("capture-pane", "-p", "-t", "=lt-old:"), "old-81-session") {
		if time.Now().After(deadline) {
			t.Fatal("the PTY-attached session never printed")
		}
		_, _ = ptmx.Write([]byte("echo old-$((9*9))-session\n"))
		time.Sleep(300 * time.Millisecond)
	}
	_ = ptmx.Close()
	_ = old.Process.Kill()
	_, _ = old.Process.Wait()

	typedHome := func(id, session, file string) string {
		t.Helper()
		h.typeLine(id, "stty raw -echo; head -c 3 > "+file+"; stty sane; echo "+file+"-$((4*4))-read")
		h.waitTmux(session, "#{pane_current_command}", "head", 10*time.Second)
		h.typeBytes(id, []byte("\x1b[H"))
		h.waitOutput(id, file+"-16-read", 15*time.Second)
		got, readErr := os.ReadFile(filepath.Join(h.home, file))
		if readErr != nil {
			t.Fatal(readErr)
		}
		return string(got)
	}

	id := h.open("lt-old", 100, 30)
	h.waitOutput(id, "old-81-session", 10*time.Second)
	if got := typedHome(id, "lt-old", "old-home"); got != "\x1b[1" {
		t.Fatalf("Home in a PTY-path session arrived as %q, want the tmux code", got)
	}
	fresh := h.open("lt-fresh", 100, 30)
	h.ready(fresh)
	if got := typedHome(fresh, "lt-fresh", "new-home"); got != "\x1b[H" {
		t.Fatalf("Home in a new session arrived as %q, want the xterm code", got)
	}
	h.typeLine(fresh, "echo term-$TERM-inside")
	h.waitOutput(fresh, "term-xterm-256color-inside", 10*time.Second)
}

// A question left in the output would be answered twice, by tmux and by the
// browser, and the second answer lands at the prompt as typed text. A
// look-alike removed by mistake would break cursor style or a soft reset.
func TestTerminalQueryFilterRemovesQuestionsOnly(t *testing.T) {
	questions := []string{"\x1b[c", "\x1b[0c", "\x1b[>c", "\x1b[=c", "\x1b[5n", "\x1b[6n", "\x1b[?6n", "\x1b[?996n",
		"\x1b[?2004$p", "\x1b[4$p", "\x1b[>q", "\x1b[>0q", "\x1b[?u", "\x1b[18t", "\x1b[14t",
		"\x1b]10;?\x07", "\x1b]11;?\x1b\\", "\x1b]4;1;?\x07", "\x1b]52;c;?\x07", "\x1bP$qm\x1b\\", "\x1bP+q544e\x1b\\"}
	kept := []string{"\x1b[2 q", "\x1b[!p", "\x1b[>4;2m", "\x1b[>1u", "\x1b[u", "\x1b[22;0;0t", "\x1b[?25h", "\x1b[1;1H",
		"\x1b[38;5;196m", "\x1b]0;a title?\x07", "\x1b]8;;http://example.com/?q=1\x1b\\", "\x1bPq#0;2;0;0;0\x1b\\",
		"\x1b[?1049h", "\x1bc", "\x1b=", "\x1b]11;rgb:0000/0000/0000\x07", "\x1b[4h", "\x1b[>0n"}
	for _, chunk := range []int{1, 2, 3, 1 << 20} {
		var stream, want []byte
		for i := range max(len(questions), len(kept)) {
			text := fmt.Sprintf("text %d ", i)
			stream, want = append(stream, text...), append(want, text...)
			if i < len(questions) {
				stream = append(stream, questions[i]...)
			}
			if i < len(kept) {
				stream, want = append(stream, kept[i]...), append(want, kept[i]...)
			}
		}
		var filter terminalQueryFilter
		var got []byte
		for len(stream) > 0 {
			n := min(chunk, len(stream))
			got = filter.apply(got, stream[:n])
			stream = stream[n:]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("in pieces of %d:\n got %q\nwant %q", chunk, got, want)
		}
	}
}

// The version gate decides between this path and the PTY one. Reading "3.10"
// as older than "3.2", or taking a 3.1 for control mode, picks the wrong one.
func TestTmuxSupportsControlFromVersionText(t *testing.T) {
	for version, want := range map[string]bool{
		"tmux 3.2": true, "tmux 3.2a": true, "tmux 3.5a": true, "tmux 3.8": true, "tmux 3.10": true, "tmux 4.0": true,
		"tmux next-3.6": true, "tmux 3.1c": false, "tmux 3.0a": false, "tmux 2.9a": false, "tmux 1.8": false,
		"tmux master": false, "tmux openbsd-7.6": false, "": false, "3.5a": false,
	} {
		if got := tmuxSupportsControl(version); got != want {
			t.Errorf("tmuxSupportsControl(%q) = %v, want %v", version, got, want)
		}
	}
}
