package remoteaccess

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
)

const (
	// One control-mode line. tmux writes pane output in lines of a few
	// kilobytes; a captured screen line can be longer.
	tmuxMaxLineBytes = 8 << 20
	// The lines kept for one reply. A longer reply keeps its end, which for a
	// captured screen is the part nearest the cursor.
	tmuxMaxReplyBytes = 16 << 20
	// Commands waiting for their reply. Typing adds one per send-keys line.
	tmuxMaxPendingReplies = 16384
)

var (
	errTmuxClientEnded = errors.New("tmux control client ended")
	errTmuxBacklog     = errors.New("tmux control client has too many commands waiting")
)

// tmuxReply is the answer to one command line: one block of lines per command
// on that line. An error ends the line early, as tmux drops the rest.
type tmuxReply struct {
	blocks [][][]byte
	failed string // text of the %error block
	lost   bool   // the client ended before the reply came
}

func (r tmuxReply) err() error {
	switch {
	case r.lost:
		return errTmuxClientEnded
	case r.failed != "":
		return errors.New(r.failed)
	}
	return nil
}

// first is the first line of a block, or "" when the block is missing or empty.
func (r tmuxReply) first(block int) string {
	if block >= len(r.blocks) || len(r.blocks[block]) == 0 {
		return ""
	}
	return string(r.blocks[block][0])
}

type tmuxPendingReply struct {
	want  int
	bytes int
	reply tmuxReply
	then  func(tmuxReply)
}

// tmuxControlClient is one `tmux -C` process on pipes. Commands go in on
// stdin and are answered in order; everything else on stdout is a
// notification, handed to notify on the reader goroutine.
type tmuxControlClient struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{} // closed once the process has ended

	writeMu sync.Mutex // one command line and its reply slot at a time
	mu      sync.Mutex
	waiting []*tmuxPendingReply
	ended   bool
}

// startTmuxControlClient starts cmd with pipes and reads it until it ends.
// notify and ended run on the reader goroutine and must not wait for a reply.
func startTmuxControlClient(cmd *exec.Cmd, notify func(line []byte), ended func()) (*tmuxControlClient, error) {
	childIn, stdin, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdout, childOut, err := os.Pipe()
	if err != nil {
		_ = childIn.Close()
		_ = stdin.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = childIn, childOut, nil
	err = cmd.Start()
	_ = childIn.Close()
	_ = childOut.Close()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	client := &tmuxControlClient{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	go client.read(stdout, notify, ended)
	return client, nil
}

// send writes one command line. then, if set, gets the reply on the reader
// goroutine before the next line is read, so it can change how the lines that
// follow are handled.
func (c *tmuxControlClient) send(line string, commands int, then func(tmuxReply)) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.ended {
		c.mu.Unlock()
		return errTmuxClientEnded
	}
	if len(c.waiting) >= tmuxMaxPendingReplies {
		c.mu.Unlock()
		return errTmuxBacklog
	}
	c.waiting = append(c.waiting, &tmuxPendingReply{want: commands, then: then})
	c.mu.Unlock()
	_, err := io.WriteString(c.stdin, line+"\n")
	return err
}

// call sends one line and waits for its reply.
func (c *tmuxControlClient) call(ctx context.Context, line string, commands int) (tmuxReply, error) {
	result := make(chan tmuxReply, 1)
	if err := c.send(line, commands, func(reply tmuxReply) { result <- reply }); err != nil {
		return tmuxReply{}, err
	}
	select {
	case reply := <-result:
		return reply, reply.err()
	case <-ctx.Done():
		return tmuxReply{}, ctx.Err()
	}
}

// kill ends the client process. The tmux session keeps running: this is a
// detach, the same as a dropped connection.
func (c *tmuxControlClient) kill() {
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

func (c *tmuxControlClient) read(stdout *os.File, notify func([]byte), ended func()) {
	defer close(c.done)
	reader := bufio.NewReaderSize(stdout, 64<<10)
	var (
		stamp   []byte // of the open reply block
		own     bool
		lines   [][]byte
		pending *tmuxPendingReply
	)
	for {
		line, err := readTmuxLine(reader)
		if err != nil {
			break
		}
		if stamp == nil {
			if begin, ok := tmuxGuardStamp(line, "%begin"); ok {
				stamp = append([]byte{}, begin...)
				own = tmuxGuardIsOwn(stamp)
				lines = nil
				pending = nil
				if own {
					pending = c.head()
				}
				continue
			}
			notify(line)
			continue
		}
		failed := false
		end, isEnd := tmuxGuardStamp(line, "%end")
		if !isEnd {
			end, isEnd = tmuxGuardStamp(line, "%error")
			failed = isEnd
		}
		if !isEnd || !bytes.Equal(end, stamp) {
			if pending != nil {
				lines = append(lines, append([]byte{}, line...))
				pending.bytes += len(line)
				for pending.bytes > tmuxMaxReplyBytes && len(lines) > 1 {
					pending.bytes -= len(lines[0])
					lines[0] = nil
					lines = lines[1:]
				}
			}
			continue
		}
		stamp = nil
		if pending == nil {
			continue
		}
		if failed {
			pending.reply.failed = string(bytes.Join(lines, []byte(" ")))
			if pending.reply.failed == "" {
				pending.reply.failed = "tmux command failed"
			}
		} else {
			pending.reply.blocks = append(pending.reply.blocks, lines)
		}
		if failed || len(pending.reply.blocks) >= pending.want {
			c.pop(pending)
			if pending.then != nil {
				pending.then(pending.reply)
			}
		}
	}
	_ = stdout.Close()
	c.mu.Lock()
	c.ended = true
	waiting := c.waiting
	c.waiting = nil
	c.mu.Unlock()
	for _, lost := range waiting {
		if lost.then != nil {
			lost.reply.lost = true
			lost.then(lost.reply)
		}
	}
	ended()
	_ = c.stdin.Close()
	_ = c.cmd.Wait()
}

func (c *tmuxControlClient) head() *tmuxPendingReply {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.waiting) == 0 {
		return nil
	}
	return c.waiting[0]
}

func (c *tmuxControlClient) pop(done *tmuxPendingReply) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.waiting) > 0 && c.waiting[0] == done {
		c.waiting[0] = nil
		c.waiting = c.waiting[1:]
	}
}

// readTmuxLine returns one line without its newline. The slice is only valid
// until the next call.
func readTmuxLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if err == nil {
		return line[:len(line)-1], nil
	}
	if !errors.Is(err, bufio.ErrBufferFull) {
		return nil, err
	}
	long := append([]byte{}, line...)
	for {
		line, err = reader.ReadSlice('\n')
		long = append(long, line...)
		if err == nil {
			return long[:len(long)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		if len(long) > tmuxMaxLineBytes {
			return nil, errors.New("tmux control line too long")
		}
	}
}
