package remoteaccess

import (
	"io"
	"os/exec"
)

// nativeTerminal is a shell on a platform without a Unix PTY: a Windows
// pseudo console, or plain pipes where there is none.
type nativeTerminal struct {
	input  io.WriteCloser
	output io.ReadCloser
	done   <-chan error // the shell's exit
	// resize is nil for plain pipes, which have no size.
	resize func(cols, rows uint16)
	// stop ends the shell and every program it started. It is nil for plain
	// pipes: there the command's context ends the shell alone.
	stop func()
}

func startPipeTerminal(cmd *exec.Cmd) (*nativeTerminal, error) {
	input, output, done, err := startPipeBackedTerminal(cmd)
	if err != nil {
		return nil, err
	}
	return &nativeTerminal{input: input, output: output, done: done}, nil
}
