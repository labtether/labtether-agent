//go:build unix

package remoteaccess

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// x11LockHeld reports whether an X server's lock file belongs to a running
// process. The agent stops its Xvfb with SIGKILL, which leaves the lock (and
// socket) behind; a stale lock made the next Remote View session treat the
// dead display as live and fail with "VNC server not ready" instead of
// starting a new Xvfb.
//
// /tmp is world-writable and the agent runs as root, so the lock is opened
// without following links and without blocking, and at most 32 bytes are
// read. Anything that is not a plain readable file holding a PID (a link, a
// FIFO, a device, a file it cannot open) counts as held, as a lock file always
// did, so the agent never starts its Xvfb on that display. Only a missing
// file or the PID of a process that is gone counts as free.
func x11LockHeld(path string) bool {
	pid, missing := readX11LockPID(path)
	if missing {
		return false
	}
	if pid <= 0 {
		return true
	}
	return processAlive(pid)
}

// x11LockOwnedBy reports whether an X server's lock file names this live
// process, so a display the agent started is still the agent's own and not a
// server someone else started on the same number after it exited.
func x11LockOwnedBy(path string, pid int) bool {
	lockPID, _ := readX11LockPID(path)
	return pid > 0 && lockPID == pid && processAlive(pid)
}

// readX11LockPID reads the PID in an X lock file. missing is true only when
// there is no file; pid is 0 when the file is anything but a plain file
// holding a PID.
func readX11LockPID(path string) (pid int, missing bool) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, errors.Is(err, syscall.ENOENT)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	data, err := io.ReadAll(io.LimitReader(file, 32))
	if err != nil {
		return 0, false
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, false
}

// processAlive reports whether a process with this PID exists.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
