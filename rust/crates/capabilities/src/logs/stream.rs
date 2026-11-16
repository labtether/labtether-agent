//! The live log stream: Go's `LogManager.Start` (`log_handler.go`) and
//! `LinuxLogBackend.StreamEntries` (`log_backend_journalctl.go`).
//!
//! `journalctl --follow --output=json --lines=0` runs for the life of the
//! agent. New entries go to the Hub in `log.batch` messages of at most 50.
//! As in Go, there is no timer: a batch is sent when it reaches 50, when an
//! entry arrives more than 2 s after the last send (or the run's start),
//! and when the run ends. While no connection is open, entries are
//! dropped. A send that fails is dropped too; Go does not retry it.
//!
//! When `journalctl` is not in the agent's `PATH` the stream does not run.
//! When `journalctl` ends cleanly the stream stops for good. When it fails
//! (it exits with an error, the rules refuse it, its output cannot be
//! read), it starts again after 1 s, then 2, 4, 8, 16 and 32 s, the wait
//! doubling while under 30 s, as Go's. A line of 256 KiB or more is
//! skipped and the stream goes on, as the Go stream does with its fix for
//! that line (before it, Go's stream stopped there until the agent
//! restarted).

use std::time::{Duration, Instant};

use labtether_agent_core::{HubSender, Stop};
use labtether_agent_platform::command_exists;
use labtether_agent_platform::tool_output::journal::{JournalEntry, MAX_JOURNAL_LINE, parse_line};
use labtether_agent_security::{CommandPolicy, RunError, RunRequest, exit_error};
use labtether_protocol::{LogBatchData, LogStreamData, MSG_LOG_BATCH, Message};

use super::lines::Lines;
use super::{unix_now, wire};

/// Go's `LogBatchMaxEntries`.
pub(crate) const BATCH_MAX: usize = 50;
/// Go's `logBatchMaxAge`.
pub(crate) const BATCH_AGE: Duration = Duration::from_secs(2);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(30);

/// The arguments Go passes (`-f --output=json -n 0`), with full names.
pub(crate) const STREAM_ARGS: [&str; 3] = ["--follow", "--output=json", "--lines=0"];

/// How one run of the source ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StreamEnd {
    /// Go's `ErrLogStreamingUnsupported`: no `journalctl`.
    Unsupported,
    /// Go's error text; the stream starts again after a wait.
    Failed(String),
}

/// One run of a log source: entries go to `emit` until it ends or `stop`.
pub(crate) type Source<'a> =
    &'a dyn Fn(&Stop, &mut dyn FnMut(JournalEntry)) -> Result<(), StreamEnd>;

/// Entries waiting to be sent.
struct Batch {
    entries: Vec<LogStreamData>,
    flush_at: Instant,
}

impl Batch {
    fn new(now: Instant) -> Self {
        Self {
            entries: Vec::with_capacity(BATCH_MAX),
            flush_at: now + BATCH_AGE,
        }
    }

    fn offer(&mut self, sender: &dyn HubSender, entry: JournalEntry, now: Instant) {
        if !sender.connected() {
            return;
        }
        self.entries.push(wire(entry));
        if self.entries.len() >= BATCH_MAX || now > self.flush_at {
            self.flush(sender, now);
        }
    }

    fn flush(&mut self, sender: &dyn HubSender, now: Instant) {
        if self.entries.is_empty() {
            return;
        }
        let entries = std::mem::take(&mut self.entries);
        self.flush_at = now + BATCH_AGE;
        if !sender.connected() {
            return;
        }
        let data = LogBatchData {
            asset_id: sender.asset_id(),
            entries,
        };
        match Message::with_data(MSG_LOG_BATCH, "", &data) {
            Ok(message) => {
                if let Err(error) = sender.send(&message) {
                    log::debug!("logmgr: log batch not sent: {error}");
                }
            }
            Err(error) => log::warn!("logmgr: failed to marshal log batch: {error}"),
        }
    }
}

/// Runs the stream until `stop`, or until the source ends cleanly or is
/// unsupported. `now` is the clock the batch age is measured with.
pub(crate) fn run(
    sender: &dyn HubSender,
    stop: &Stop,
    source: Source<'_>,
    now: &dyn Fn() -> Instant,
) {
    let mut backoff = FIRST_BACKOFF;
    loop {
        let mut batch = Batch::new(now());
        let result = source(stop, &mut |entry| batch.offer(sender, entry, now()));
        batch.flush(sender, now());
        if stop.is_stopped() {
            return;
        }
        let error = match result {
            Ok(()) | Err(StreamEnd::Unsupported) => return,
            Err(StreamEnd::Failed(error)) => error,
        };
        log::warn!("logmgr: stream backend error (restarting in {backoff:?}): {error}");
        if stop.wait(backoff) {
            return;
        }
        if backoff < BACKOFF_CEILING {
            backoff *= 2;
        }
    }
}

/// One run of `journalctl --follow` through the command rules.
pub(crate) fn journal(
    policy: &CommandPolicy,
    stop: &Stop,
    emit: &mut dyn FnMut(JournalEntry),
) -> Result<(), StreamEnd> {
    if !command_exists("journalctl", policy.search_path()) {
        return Err(StreamEnd::Unsupported);
    }
    let request = RunRequest::new("journalctl", STREAM_ARGS);
    let mut started = match policy.start_streaming(&request) {
        Ok(started) => started,
        Err(RunError::Refused(refusal)) => {
            return Err(StreamEnd::Failed(format!(
                "failed to build journalctl stream command: {refusal}"
            )));
        }
        Err(error) => {
            return Err(StreamEnd::Failed(format!(
                "failed to start journalctl: {error}"
            )));
        }
    };
    let stopper = started.stopper();
    let _hook = stop.on_stop(move || stopper.stop());
    let Some(stdout) = started.take_stdout() else {
        return Err(StreamEnd::Failed(
            "failed to open journalctl stdout pipe".to_owned(),
        ));
    };
    let mut lines = Lines::new(stdout, MAX_JOURNAL_LINE);
    let scan_error = loop {
        match lines.next_line() {
            Ok(Some(line)) => {
                if stop.is_stopped() {
                    break None;
                }
                if let Some(entry) = parse_line(&line, unix_now) {
                    emit(entry);
                }
            }
            Ok(None) => break None,
            Err(error) => break Some(error),
        }
    };
    // After a failed read nothing reads journalctl's output any more, so
    // it would never end; this ends it before the wait.
    if scan_error.is_some() {
        started.stopper().stop();
    }
    drop(lines);
    let status = started.wait();
    if stop.is_stopped() {
        return Ok(());
    }
    if let Some(error) = scan_error {
        return Err(StreamEnd::Failed(format!(
            "journalctl scanner error: {error}"
        )));
    }
    match status {
        Ok(status) => match exit_error(status).0 {
            None => Ok(()),
            Some(error) => Err(StreamEnd::Failed(format!(
                "journalctl stream failed: {error}"
            ))),
        },
        Err(error) => Err(StreamEnd::Failed(format!(
            "journalctl stream failed: {error}"
        ))),
    }
}
