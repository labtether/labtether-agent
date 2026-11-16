//! The one entry point that starts a process: Go's `NewCommandContext` with
//! `CaptureCombinedOutput` or `CaptureOutput`, plus the process-group stop
//! of the Go agent's remote command path (`exec_capture.go`).

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use labtether_agent_config::gopath;
use labtether_agent_platform::{LookPathError, look_path, process};

use crate::capture::{join, reader_channel, spawn_reader, wait_for_readers};
use crate::error::Refusal;
use crate::gotext::quote;
use crate::lists::{COMMAND_STDERR_CAPTURE_LIMIT, DEFAULT_COMMAND_OUTPUT_LIMIT};
use crate::policy::CommandPolicy;

/// Which output is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capture {
    /// Go's `CaptureCombinedOutput`: stdout and stderr share one pipe, in
    /// the order the command wrote them.
    Combined,
    /// Go's `CaptureOutput`: stdout up to the limit, stderr up to 64 KiB.
    Stdout,
}

/// The default [`RunRequest::wait_delay`], the Go agent's remote command
/// value (`remoteCommandOutputDrainTimeout`).
pub const DEFAULT_WAIT_DELAY: Duration = Duration::from_secs(1);

/// A command to start. Build with [`RunRequest::new`] and adjust fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    /// A bare name looked up in the agent's `PATH`, or a path.
    pub program: String,
    pub args: Vec<String>,
    pub capture: Capture,
    /// Bytes of output kept (Go's `DefaultCommandOutputLimit`, 8 MiB).
    pub output_limit: usize,
    /// Go's context deadline. When it passes, the command's whole process
    /// group gets SIGKILL. `None` waits as long as the command runs.
    pub timeout: Option<Duration>,
    /// Go's `exec.Cmd.WaitDelay`: how long to wait for the output pipes to
    /// close after the command ends; then the pipes are closed and
    /// `output_held` is set. 1 s by default, as Go's remote command path.
    /// `None` waits until every descendant holding a pipe has ended, which
    /// can be forever (a started daemon); after a timeout the wait is
    /// bounded by [`DEFAULT_WAIT_DELAY`] even then.
    pub wait_delay: Option<Duration>,
    /// Variables set for this command on top of the sanitized environment;
    /// a name already there gets this value. Empty by default.
    pub env_overrides: Vec<(String, String)>,
}

impl RunRequest {
    /// Combined output, the 8 MiB limit, no timeout, a 1 s wait delay.
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            capture: Capture::Combined,
            output_limit: DEFAULT_COMMAND_OUTPUT_LIMIT,
            timeout: None,
            wait_delay: Some(DEFAULT_WAIT_DELAY),
            env_overrides: Vec::new(),
        }
    }
}

/// A command that started and ended.
#[derive(Debug)]
pub struct Finished {
    /// Combined output, or stdout, at most the limit.
    pub output: Vec<u8>,
    /// With [`Capture::Stdout`], stderr up to 64 KiB; otherwise empty.
    pub stderr: Vec<u8>,
    /// Output went past the limit and was cut (Go's `ErrCommandOutputLimit`).
    pub truncated: bool,
    pub status: ExitStatus,
    /// The timeout passed and the process group was stopped.
    pub timed_out: bool,
    /// A pipe was still open when `wait_delay` ran out (Go's
    /// `exec.ErrWaitDelay`): a descendant still holds the command's output.
    pub output_held: bool,
}

impl Finished {
    /// True where Go's helpers return no error.
    pub fn succeeded(&self) -> bool {
        self.status.success() && !self.truncated && !self.timed_out && !self.output_held
    }

    /// The signal that ended the command, if one did.
    pub fn signal(&self) -> Option<i32> {
        self.status.signal()
    }
}

/// Why a command did not run to an end.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Refused(#[from] Refusal),
    #[error("command output limit must be positive")]
    InvalidLimit,
    #[error("exec: {}: executable file not found in $PATH", quote(.0))]
    NotFound(String),
    #[error("exec: {}: cannot run executable found relative to current directory", quote(.0))]
    RelativeToCurrentDir(String),
    #[error("{0}")]
    Start(std::io::Error),
    #[error("{0}")]
    Wait(std::io::Error),
}

impl CommandPolicy {
    /// Go's `NewValidatedShellCommandContext`: checks a command line against
    /// the shell rules and returns it as a request. [`CommandPolicy::run`]
    /// then checks the program against the exec rules, as Go does.
    pub fn command_line_request(&self, line: &str) -> Result<RunRequest, Refusal> {
        let mut args = self.validate_shell_command(line)?;
        let program = args.remove(0);
        Ok(RunRequest::new(program, args))
    }

    /// Starts `request` and waits for it. This is the only way the agent
    /// starts a process. Before anything starts, the program is checked
    /// against the exec rules; a full path starts the file `PATH` finds for
    /// its name, under the name as given. The command gets the sanitized environment,
    /// no stdin, and its own process group. It blocks the calling thread;
    /// async callers use `spawn_blocking`.
    pub fn run(&self, request: &RunRequest) -> Result<Finished, RunError> {
        let checked = self.resolve_exec_program(&request.program)?;
        if request.output_limit == 0 {
            return Err(RunError::InvalidLimit);
        }
        let path = match checked {
            Some(path) => path,
            None => self.resolve(&request.program)?,
        };
        // The one place a process is started (see rust/clippy.toml).
        #[allow(clippy::disallowed_methods)]
        let mut command = std::process::Command::new(path);
        command
            .arg0(&request.program)
            .args(&request.args)
            .env_clear()
            .envs(self.child_env.iter().map(|(key, value)| (key, value)))
            .envs(
                request
                    .env_overrides
                    .iter()
                    .map(|(key, value)| (key, value)),
            )
            .stdin(Stdio::null())
            .process_group(0);

        // Dropping `cancel_tx` stops every reader still waiting on a pipe.
        // Both ends are close-on-exec, so the command never inherits them.
        let (cancel, cancel_tx) = std::io::pipe().map_err(RunError::Start)?;
        let cancel_out = cancel.try_clone().map_err(RunError::Start)?;
        let cancel_err = cancel.try_clone().map_err(RunError::Start)?;
        drop(cancel);
        let (done, done_rx) = reader_channel();
        let (output, stderr, readers);
        let mut child;
        match request.capture {
            Capture::Combined => {
                let (reader, writer) = std::io::pipe().map_err(RunError::Start)?;
                let writer_err = writer.try_clone().map_err(RunError::Start)?;
                command.stdout(writer).stderr(writer_err);
                child = command.spawn().map_err(RunError::Start)?;
                // The command holds the pipe's write ends; drop them so the
                // reader sees the end once the child and its descendants do.
                drop(command);
                output = spawn_reader(reader, request.output_limit, cancel_out, &done);
                stderr = None;
                readers = 1;
            }
            Capture::Stdout => {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
                child = command.spawn().map_err(RunError::Start)?;
                drop(command);
                let out = child.stdout.take().ok_or_else(missing_pipe)?;
                let err = child.stderr.take().ok_or_else(missing_pipe)?;
                output = spawn_reader(out, request.output_limit, cancel_out, &done);
                stderr = Some(spawn_reader(
                    err,
                    COMMAND_STDERR_CAPTURE_LIMIT,
                    cancel_err,
                    &done,
                ));
                readers = 2;
            }
        }

        let mut waiter = None;
        let timed_out = match request.timeout {
            None => false,
            Some(timeout) => {
                let pid = child.id();
                let (ended, ended_rx) = channel();
                waiter = Some(thread::spawn(move || {
                    let _ = process::wait_ended(pid);
                    let _ = ended.send(());
                }));
                let expired = matches!(
                    ended_rx.recv_timeout(timeout),
                    Err(RecvTimeoutError::Timeout)
                );
                if expired && process::kill_group(pid).is_err() {
                    let _ = child.kill();
                }
                expired
            }
        };
        // Join the waiter before the child is reaped: it waits on the child's
        // process ID, which stays reserved only until then.
        if let Some(waiter) = waiter {
            let _ = waiter.join();
        }
        let status = child.wait();
        // After a timeout a descendant that left the group (setsid) can still
        // hold a pipe, so the drain is always bounded then.
        let bound = if timed_out {
            Some(request.wait_delay.unwrap_or(DEFAULT_WAIT_DELAY))
        } else {
            request.wait_delay
        };
        let closed = wait_for_readers(&done_rx, readers, bound);
        // Stop the readers still waiting and join them, so no thread (and no
        // output buffer) outlives this call.
        drop(cancel_tx);
        let output = join(output);
        let stderr = stderr.map(join);
        let status = status.map_err(RunError::Wait)?;
        Ok(Finished {
            truncated: output.truncated(),
            output: output.bytes().to_vec(),
            stderr: stderr.map(|s| s.bytes().to_vec()).unwrap_or_default(),
            status,
            timed_out,
            output_held: !closed,
        })
    }

    /// Go's `exec.Command` lookup: only a bare name (its own `Base`) is
    /// looked up in the agent's `PATH`; anything else is used as given.
    fn resolve(&self, program: &str) -> Result<PathBuf, RunError> {
        if gopath::base(program) != program {
            return Ok(PathBuf::from(program));
        }
        look_path(program, &self.search_path).map_err(|error| match error {
            LookPathError::NotFound => RunError::NotFound(program.to_owned()),
            LookPathError::RelativeToCurrentDir => {
                RunError::RelativeToCurrentDir(program.to_owned())
            }
        })
    }
}

fn missing_pipe() -> RunError {
    RunError::Start(std::io::Error::other("command pipe missing"))
}
