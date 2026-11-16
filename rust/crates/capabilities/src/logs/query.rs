//! `journal.query`: Go's `HandleJournalQuery` and
//! `LinuxLogBackend.QueryEntries`. One `journalctl` run with Go's 20 s
//! timeout and the 8 MiB output limit, newest entries first, at most 1000.

use std::time::Duration;

use labtether_agent_platform::command_exists;
use labtether_agent_platform::tool_output::gotext::{lossy, scan_lines_max, trim_space};
use labtether_agent_platform::tool_output::journal::{MAX_JOURNAL_LINE, parse_line};
use labtether_agent_security::{CommandPolicy, RunError, RunRequest, go_outcome};
use labtether_protocol::{JournalEntriesData, JournalQueryData, LogStreamData};

use super::{unix_now, wire};

/// Go's `journalQueryCommandTimeout`.
pub(crate) const GO_TIMEOUT: Duration = Duration::from_secs(20);

/// Go's `NormalizedJournalLimit`: 200 when unset or not positive, at most
/// 1000.
pub(crate) fn normalized_limit(raw: i64) -> i64 {
    if raw <= 0 { 200 } else { raw.min(1000) }
}

/// Go's `BuildJournalQueryArgs` with full option names, each value joined
/// to its option with `=` so a value can never be read as an option. Go
/// passes `-n N -r -u U -p P`; `--lines` takes its value only after `=`.
pub(crate) fn query_args(request: &JournalQueryData) -> Vec<String> {
    let mut args = vec![
        "--no-pager".to_owned(),
        "--output=json".to_owned(),
        format!("--lines={}", normalized_limit(request.limit)),
        "--reverse".to_owned(),
    ];
    let options = [
        ("--since", &request.since),
        ("--until", &request.until),
        ("--unit", &request.unit),
        ("--priority", &request.priority),
        ("--grep", &request.search),
    ];
    for (option, value) in options {
        let value = value.trim();
        if !value.is_empty() {
            args.push(format!("{option}={value}"));
        }
    }
    args
}

/// The entries, or Go's error text. Blocks: run it on a worker thread.
pub(crate) fn query(
    policy: &CommandPolicy,
    request: &JournalQueryData,
    timeout: Duration,
) -> Result<Vec<LogStreamData>, String> {
    if !command_exists("journalctl", policy.search_path()) {
        return Err("journalctl is not available on this host".to_owned());
    }
    let mut run = RunRequest::new("journalctl", query_args(request));
    run.timeout = Some(timeout);
    let result = match policy.run(&run) {
        Err(RunError::Refused(refusal)) => {
            return Err(format!(
                "journalctl command blocked by runtime policy: {refusal}"
            ));
        }
        other => other,
    };
    let outcome = go_outcome(result, run.output_limit);
    if let Some(error) = outcome.error {
        if outcome.timed_out {
            return Err("journalctl query timed out".to_owned());
        }
        let output = trim_space(&outcome.output);
        return Err(if output.is_empty() {
            format!("journalctl query failed: {error}")
        } else {
            format!("journalctl query failed: {}", lossy(output))
        });
    }
    let (lines, scanned) = scan_lines_max(&outcome.output, MAX_JOURNAL_LINE);
    if let Err(error) = scanned {
        return Err(format!("failed to parse journal output: {error}"));
    }
    Ok(lines
        .into_iter()
        .filter_map(|line| parse_line(line, unix_now))
        .map(wire)
        .collect())
}

/// The reply: the entries, or the error and none.
pub(crate) fn answer(
    policy: &CommandPolicy,
    request: JournalQueryData,
    timeout: Duration,
) -> JournalEntriesData {
    match query(policy, &request, timeout) {
        Ok(entries) => JournalEntriesData {
            request_id: request.request_id,
            entries,
            error: String::new(),
        },
        Err(error) => {
            log::warn!("journal: failed to query entries: {error}");
            JournalEntriesData {
                request_id: request.request_id,
                entries: Vec::new(),
                error,
            }
        }
    }
}
