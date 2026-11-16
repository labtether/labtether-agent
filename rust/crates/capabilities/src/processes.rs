//! The Processes page: `process.list`, ported from Go's `HandleProcessList`
//! (`internal/agentcore/system/process.go`): sort by CPU (default) or
//! memory, highest first, then keep the first `limit` (default 25, no upper
//! bound in the agent; the Hub caps it at 200). Advertised as
//! `cap_processes=list`; Go advertises nothing for it and the Hub offers
//! the process list to every Go agent.
//!
//! Go reads the list from `ps`; this agent reads `/proc` with `ps`'s rules
//! (see `labtether_agent_platform::procps`). Processes with equal values
//! keep PID order here; Go's sort is not stable, so its order among equal
//! values is whatever its sort leaves.
//!
//! `process.kill` is not in this agent and is not registered or
//! advertised, so the Hub refuses it without sending it.

use std::cmp::Ordering;

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::processes::{self, ProcessRow};
use labtether_agent_platform::procps::TextMode;
use labtether_protocol::{
    MSG_PROCESS_LIST, MSG_PROCESS_LISTED, ProcessInfo, ProcessListData, ProcessListedData,
};

/// Go's defaults for an empty `sort_by` and a `limit` of 0 or less.
const DEFAULT_LIMIT: i64 = 25;

pub fn register(features: &mut Features, settings: &Settings) {
    let mode = if settings.utf8_locale {
        TextMode::Utf8
    } else {
        TextMode::Plain
    };
    features.on_request(
        MSG_PROCESS_LIST,
        MSG_PROCESS_LISTED,
        request_id,
        move |request| answer(request, processes::process_list(mode)),
    );
}

fn request_id(request: &ProcessListData) -> &str {
    &request.request_id
}

fn process_info(row: ProcessRow) -> ProcessInfo {
    ProcessInfo {
        pid: row.pid,
        name: row.name,
        user: row.user,
        cpu_pct: row.cpu_pct,
        mem_pct: row.mem_pct,
        mem_rss: row.mem_rss,
        command: row.command,
    }
}

fn descending(a: f64, b: f64) -> Ordering {
    b.partial_cmp(&a).unwrap_or(Ordering::Equal)
}

/// The reply for `request`: the list sorted and cut as Go does, or the
/// error and no processes.
pub(crate) fn answer(
    request: ProcessListData,
    list: std::io::Result<Vec<ProcessRow>>,
) -> ProcessListedData {
    let limit = if request.limit <= 0 {
        DEFAULT_LIMIT
    } else {
        request.limit
    };
    let (mut rows, error) = match list {
        Ok(rows) => (rows, String::new()),
        Err(error) => {
            log::warn!("process: failed to collect processes: {error}");
            (Vec::new(), error.to_string())
        }
    };
    if request.sort_by == "memory" {
        rows.sort_by(|a, b| descending(a.mem_pct, b.mem_pct));
    } else {
        rows.sort_by(|a, b| descending(a.cpu_pct, b.cpu_pct));
    }
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    ProcessListedData {
        request_id: request.request_id,
        processes: rows.into_iter().map(process_info).collect(),
        error,
    }
}
