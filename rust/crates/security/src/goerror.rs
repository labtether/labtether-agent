//! What Go's `CaptureCombinedOutput` and `CaptureOutput` hand back: the
//! kept output and the error, with Go's text (`exec.ExitError`,
//! `ErrCommandOutputLimit`, `errors.Join`), so a page can build Go's reply.

use std::os::unix::process::ExitStatusExt;

use crate::run::{Finished, RunError};

/// A command's result in Go's terms.
#[derive(Debug, Default)]
pub struct GoOutcome {
    /// The kept output (empty when the command did not start).
    pub output: Vec<u8>,
    /// Go's error text, or `None` where Go returns no error.
    pub error: Option<String>,
    /// Go's `ExitCode()`: the exit status, or -1 when there is none (not
    /// started, ended by a signal).
    pub exit_code: i32,
    /// The output went past the limit (`errors.Is(err, ErrCommandOutputLimit)`).
    pub limit_hit: bool,
    /// The timeout passed (Go's `ctx.Err() == context.DeadlineExceeded`).
    pub timed_out: bool,
}

/// Go's names for Linux signals (`syscall` signal table), by number.
const SIGNAL_NAMES: [&str; 31] = [
    "hangup",
    "interrupt",
    "quit",
    "illegal instruction",
    "trace/breakpoint trap",
    "aborted",
    "bus error",
    "floating point exception",
    "killed",
    "user defined signal 1",
    "segmentation fault",
    "user defined signal 2",
    "broken pipe",
    "alarm clock",
    "terminated",
    "stack fault",
    "child exited",
    "continued",
    "stopped (signal)",
    "stopped",
    "stopped (tty input)",
    "stopped (tty output)",
    "urgent I/O condition",
    "CPU time limit exceeded",
    "file size limit exceeded",
    "virtual timer expired",
    "profiling timer expired",
    "window changed",
    "I/O possible",
    "power failure",
    "bad system call",
];

fn signal_text(signal: i32) -> String {
    let name = usize::try_from(signal - 1)
        .ok()
        .and_then(|index| SIGNAL_NAMES.get(index));
    match name {
        Some(name) => (*name).to_owned(),
        None => format!("signal {signal}"),
    }
}

/// Go's result for a run with output limit `limit`.
pub fn go_outcome(result: Result<Finished, RunError>, limit: usize) -> GoOutcome {
    let finished = match result {
        Ok(finished) => finished,
        Err(error) => {
            return GoOutcome {
                error: Some(error.to_string()),
                exit_code: -1,
                ..GoOutcome::default()
            };
        }
    };
    let status = finished.status;
    let (run_error, exit_code) = match (status.code(), status.signal()) {
        (Some(0), _) => (None, 0),
        (Some(code), _) => (Some(format!("exit status {code}")), code),
        (None, Some(signal)) => {
            let core = if status.core_dumped() {
                " (core dumped)"
            } else {
                ""
            };
            (Some(format!("signal: {}{core}", signal_text(signal))), -1)
        }
        (None, None) => (Some(format!("{status}")), -1),
    };
    // Go's `exec.ErrWaitDelay`, reported only when the command itself
    // succeeded.
    let run_error = match run_error {
        None if finished.output_held => {
            Some("exec: WaitDelay expired before I/O complete".to_owned())
        }
        other => other,
    };
    let error = if finished.truncated {
        let limit_error = format!("command output exceeded capture limit ({limit} bytes)");
        Some(match run_error {
            Some(run) => format!("{run}\n{limit_error}"),
            None => limit_error,
        })
    } else {
        run_error
    };
    GoOutcome {
        output: finished.output,
        error,
        exit_code,
        limit_hit: finished.truncated,
        timed_out: finished.timed_out,
    }
}
