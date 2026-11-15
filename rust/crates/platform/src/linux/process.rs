//! Process control for the commands the agent starts, through safe system
//! calls. The security crate starts each command in its own process group;
//! these calls let it wait for the command and stop the whole group, as the
//! Go agent's remote command path does (`exec_process_group_unix.go`), and
//! stop reading a command's output pipe on request.

use std::io;
use std::os::fd::BorrowedFd;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};

fn to_pid(raw: u32) -> io::Result<Pid> {
    i32::try_from(raw)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
}

/// Blocks until the child `pid` has ended, without reaping it. The process
/// ID, and with it the process group ID, stay reserved until the owner of
/// the child reaps it, so a later [`kill_group`] cannot reach a stranger.
pub fn wait_ended(pid: u32) -> io::Result<()> {
    let pid = to_pid(pid)?;
    loop {
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        ) {
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Sends SIGKILL to every process in the group led by `pgid`. A group that
/// is already gone counts as stopped.
pub fn kill_group(pgid: u32) -> io::Result<()> {
    match kill_process_group(to_pid(pgid)?, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// What woke a reader in [`wait_readable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// The pipe has data or has reached its end; a read will not block.
    Data,
    /// The cancel pipe was written to or its write end was closed.
    Cancelled,
}

/// Blocks until `pipe` can be read without blocking or `cancel` signals.
/// A cancel wins over pending data, so a reader stops at once.
pub fn wait_readable(pipe: BorrowedFd<'_>, cancel: BorrowedFd<'_>) -> io::Result<Readiness> {
    loop {
        let mut fds = [
            PollFd::from_borrowed_fd(pipe, PollFlags::IN),
            PollFd::from_borrowed_fd(cancel, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        if !fds[1].revents().is_empty() {
            return Ok(Readiness::Cancelled);
        }
        if !fds[0].revents().is_empty() {
            return Ok(Readiness::Data);
        }
    }
}
