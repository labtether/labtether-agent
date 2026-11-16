//! The Logs page on Linux, ported from the Go agent's
//! `internal/agentcore/backends`: the Hub's `journal.query` answered with
//! `journal.entries` (`journal.go`, `log_backend_journalctl.go`), and the
//! live stream of new journal lines sent as `log.batch` messages the Hub
//! did not ask for (`log_handler.go`, started in `run.go`).
//!
//! `journalctl` runs only through the command rules, with full option
//! names. Advertised as Go's Linux agent does: with `journalctl` in the
//! agent's `PATH`, `cap_logs=stored,query,stream` and
//! `log_backend=journalctl`; without it `cap_logs=stored` and
//! `log_backend=none`. The query handler is there either way (it answers
//! that `journalctl` is missing), and the stream runs unless
//! `LABTETHER_LOG_STREAM_ENABLED` turns it off.

mod lines;
pub(crate) mod query;
pub(crate) mod stream;

use std::sync::Arc;

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::command_exists;
use labtether_agent_platform::tool_output::journal::JournalEntry;
use labtether_protocol::{JournalQueryData, LogStreamData, MSG_JOURNAL_ENTRIES, MSG_JOURNAL_QUERY};

use crate::Commands;

/// The producer's name.
pub const STREAM: &str = "log-stream";

pub fn register(features: &mut Features, settings: &Settings, commands: &Commands) {
    let policy = Arc::clone(&commands.policy);
    let found = command_exists("journalctl", policy.search_path());
    let query_policy = Arc::clone(&policy);
    features.on_request(
        MSG_JOURNAL_QUERY,
        MSG_JOURNAL_ENTRIES,
        request_id,
        move |request| query::answer(&query_policy, request, query::GO_TIMEOUT),
    );
    let (capability, backend) = advertisement(found);
    features.advertise("cap_logs", capability);
    features.advertise("log_backend", backend);
    if settings.log_stream_enabled {
        features.on_start(STREAM, move |sender, stop| {
            stream::run(
                sender,
                stop,
                &|stop, emit| stream::journal(&policy, stop, emit),
                &std::time::Instant::now,
            );
        });
    } else {
        log::info!(
            "{}: background log streaming disabled (LABTETHER_LOG_STREAM_ENABLED=false)",
            settings.name
        );
    }
}

/// `cap_logs` and `log_backend` for a host with or without `journalctl`.
pub(crate) fn advertisement(journalctl_found: bool) -> (&'static str, &'static str) {
    if journalctl_found {
        ("stored,query,stream", "journalctl")
    } else {
        ("stored", "none")
    }
}

fn request_id(request: &JournalQueryData) -> &str {
    &request.request_id
}

/// The wire form of an entry; Go leaves `asset_id` empty in each entry.
pub(crate) fn wire(entry: JournalEntry) -> LogStreamData {
    LogStreamData {
        asset_id: String::new(),
        timestamp: entry.timestamp,
        level: entry.level.to_owned(),
        message: entry.message,
        source: entry.source,
    }
}

/// The current Unix time in seconds, for entries without a timestamp.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
