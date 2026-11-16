//! A command whose output is read while it runs: Go's
//! `NewCommandContext`, `StdoutPipe` and `Start`, as the log stream runs
//! `journalctl --follow`. The same checks as [`CommandPolicy::run`]; stdout
//! is a pipe, stderr goes nowhere (Go leaves `cmd.Stderr` nil), and the
//! command runs until it ends or [`Stopper::stop`] ends its process group
//! (Go kills it when the context is cancelled).

use std::io;
use std::process::{Child, ChildStdout, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};

use labtether_agent_platform::process;

use crate::policy::CommandPolicy;
use crate::run::{RunError, RunRequest};

/// The process group to end, while the command has not been reaped. Once
/// it is reaped its ID can belong to another process, so it is cleared
/// first.
#[derive(Debug, Clone, Default)]
struct Group(Arc<Mutex<Option<u32>>>);

impl Group {
    fn lock(&self) -> MutexGuard<'_, Option<u32>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Ends a running [`Streaming`] command from another thread.
#[derive(Debug, Clone)]
pub struct Stopper(Group);

impl Stopper {
    /// Sends SIGKILL to the command's process group. Does nothing once the
    /// command has been reaped.
    pub fn stop(&self) {
        if let Some(pid) = *self.0.lock() {
            let _ = process::kill_group(pid);
        }
    }
}

/// A started command; read its output with [`Streaming::take_stdout`],
/// then [`Streaming::wait`]. Dropped without a wait, it is stopped and
/// reaped.
#[derive(Debug)]
pub struct Streaming {
    child: Child,
    stdout: Option<ChildStdout>,
    group: Group,
}

impl CommandPolicy {
    /// Starts `request` with its output to be read as it comes. Uses the
    /// program, arguments and environment overrides of `request`; its
    /// capture, limit, timeout and wait delay do not apply.
    pub fn start_streaming(&self, request: &RunRequest) -> Result<Streaming, RunError> {
        let mut command = self.command(request)?;
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = command.spawn().map_err(RunError::Start)?;
        let stdout = child.stdout.take();
        let group = Group::default();
        *group.lock() = Some(child.id());
        Ok(Streaming {
            child,
            stdout,
            group,
        })
    }
}

impl Streaming {
    /// The command's stdout, once.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// A handle that ends the command from another thread.
    pub fn stopper(&self) -> Stopper {
        Stopper(self.group.clone())
    }

    /// Waits for the command to end and reaps it. A [`Stopper`] does
    /// nothing after this.
    pub fn wait(mut self) -> io::Result<ExitStatus> {
        self.reap()
    }

    fn reap(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdout.take());
        // Wait without reaping, so the ID stays reserved while a stopper
        // may still use it; then clear it and reap.
        let _ = process::wait_ended(self.child.id());
        *self.group.lock() = None;
        self.child.wait()
    }
}

impl Drop for Streaming {
    fn drop(&mut self) {
        if self.group.lock().is_some() {
            self.stopper().stop();
            let _ = self.reap();
        }
    }
}
