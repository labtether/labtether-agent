//! `LABTETHER_PARENT_PID`: the macOS and Windows apps start the agent as a
//! child and set this, so the agent stops when the app is gone. Ported from
//! the Go agent's `cmd/labtether-agent/parent_lifetime.go` and
//! `parent_lifetime_unix.go`: a value that is not a positive process ID, or
//! names the agent itself, or a process that is already gone stops the
//! start; then the process is checked every 250 ms with signal 0, and a
//! permission refusal still counts as alive.
//!
//! Signal 0 works the same on Linux and macOS (`rustix`, no `unsafe` here).
//! Windows needs a process handle wait instead, as Go's
//! `parent_lifetime_windows.go` does.

use std::fmt;
use std::time::Duration;

use labtether_agent_config::ParentPid;
use rustix::io::Errno;
use rustix::process::{Pid, test_kill_process};

/// Go's ticker interval.
pub const POLL: Duration = Duration::from_millis(250);

/// Why the agent does not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentError {
    Invalid,
    OwnPid,
    Inspect { pid: i32, error: Errno },
}

impl fmt::Display for ParentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("LABTETHER_PARENT_PID must be a positive process ID"),
            Self::OwnPid => f.write_str("LABTETHER_PARENT_PID cannot reference the agent itself"),
            Self::Inspect { pid, error } => {
                write!(f, "monitor PID {pid}: inspect process: {error}")
            }
        }
    }
}

/// Signal 0 to `pid`: `Ok` while the process exists.
pub fn probe(pid: i32) -> Result<(), Errno> {
    let pid = Pid::from_raw(pid).ok_or(Errno::INVAL)?;
    alive(test_kill_process(pid))
}

/// A permission refusal means the process exists and belongs to someone
/// else (an app run by another user).
fn alive(signal_zero: Result<(), Errno>) -> Result<(), Errno> {
    match signal_zero {
        Ok(()) | Err(Errno::PERM) => Ok(()),
        Err(error) => Err(error),
    }
}

/// The process to watch, or `None` when no parent is set.
pub fn check(
    setting: ParentPid,
    own_pid: u32,
    probe: impl Fn(i32) -> Result<(), Errno>,
) -> Result<Option<i32>, ParentError> {
    let pid = match setting {
        ParentPid::Unset => return Ok(None),
        ParentPid::Invalid => return Err(ParentError::Invalid),
        ParentPid::Pid(pid) => pid,
    };
    if u32::try_from(pid).is_ok_and(|pid| pid == own_pid) {
        return Err(ParentError::OwnPid);
    }
    probe(pid).map_err(|error| ParentError::Inspect { pid, error })?;
    Ok(Some(pid))
}

/// Returns once `probe` says the process is gone, checking every `every`.
pub async fn wait_gone(pid: i32, every: Duration, probe: impl Fn(i32) -> Result<(), Errno>) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        ticks.tick().await;
        if probe(pid).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use super::*;

    // Faults: a bad value or the agent's own PID is accepted, so the agent
    // outlives the app; a parent owned by another user (EPERM) counts as
    // gone and the agent stops at once; a parent already gone is watched
    // instead of refused.
    #[test]
    fn check_follows_go() {
        let exists = |_| Ok(());
        assert_eq!(check(ParentPid::Unset, 10, exists), Ok(None));
        assert_eq!(
            check(ParentPid::Invalid, 10, exists),
            Err(ParentError::Invalid)
        );
        assert_eq!(
            check(ParentPid::Pid(10), 10, exists),
            Err(ParentError::OwnPid)
        );
        assert_eq!(check(ParentPid::Pid(11), 10, exists), Ok(Some(11)));
        let gone = |_| Err(Errno::SRCH);
        assert_eq!(
            check(ParentPid::Pid(11), 10, gone),
            Err(ParentError::Inspect {
                pid: 11,
                error: Errno::SRCH
            })
        );
        // EPERM counts as alive; the tests run as root, so the real probe
        // never sees it here.
        assert_eq!(alive(Err(Errno::PERM)), Ok(()));
        assert_eq!(alive(Err(Errno::SRCH)), Err(Errno::SRCH));
        assert_eq!(probe(std::process::id() as i32), Ok(()));
        assert_eq!(probe(0), Err(Errno::INVAL));
    }

    // Fault: the watch never notices the parent is gone, or stops while it
    // is still there.
    #[tokio::test(start_paused = true)]
    async fn wait_gone_returns_after_the_parent_ends() {
        let checks = AtomicU32::new(0);
        let probe = |_| {
            if checks.fetch_add(1, Ordering::Relaxed) < 3 {
                Ok(())
            } else {
                Err(Errno::SRCH)
            }
        };
        let started = tokio::time::Instant::now();
        wait_gone(42, POLL, probe).await;
        assert_eq!(checks.load(Ordering::Relaxed), 4);
        assert_eq!(started.elapsed(), Duration::from_millis(1000));
    }
}
