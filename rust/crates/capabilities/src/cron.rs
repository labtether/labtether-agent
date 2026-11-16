//! The Scheduled jobs page: `cron.list`, ported from Go's `HandleCronList`
//! and `LinuxCronBackend` (`internal/agentcore/backends/cron_handler.go`,
//! `cron_backend_systemd.go`). Go's Linux agent always advertises
//! `cap_schedules=list`, and so does this (from the handler).
//!
//! The reply lists systemd timers, then crontab lines. Go runs
//! `systemctl list-timers --all --no-pager --plain` with the 8 MiB combined
//! output limit and no timeout; when `systemctl` is not installed it skips
//! timers without an error. Here the same command runs through the command
//! rules. Unlike Go, which starts this `systemctl` without its command
//! rules (all of the agent's environment, no allowlist check), it gets the
//! cleaned environment and a blocked `systemctl` is refused.
//!
//! An error from either source is sent with whatever the other gave, as
//! `systemd timers: ...; crontabs: ...`.

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::command_exists;
use labtether_agent_platform::cron::crontab::{CrontabPaths, collect_crontabs};
use labtether_agent_platform::cron::timers::parse_list_timers;
use labtether_agent_platform::cron::{Entry, combine_errors};
use labtether_agent_platform::gotime::{Zone, local_zone};
use labtether_agent_security::{CommandPolicy, RunRequest, go_outcome};
use labtether_protocol::{CronEntry, CronListData, CronListedData, MSG_CRON_LIST, MSG_CRON_LISTED};

use crate::commands::Commands;

pub fn register(features: &mut Features, settings: &Settings, commands: &Commands) {
    // Go's `time.Local`, read once for the life of the agent.
    let zone = local_zone(settings.time_zone.as_deref());
    let policy = commands.policy.clone();
    features.on_request(MSG_CRON_LIST, MSG_CRON_LISTED, request_id, move |request| {
        let timers = collect_timers(&policy, &zone);
        answer(request, timers, collect_crontabs(&CrontabPaths::default()))
    });
}

fn request_id(request: &CronListData) -> &str {
    &request.request_id
}

/// The `systemctl` Go runs: these arguments, no timeout, Go's output limit.
pub(crate) fn timers_request() -> RunRequest {
    let mut request = RunRequest::new(
        "systemctl",
        ["list-timers", "--all", "--no-pager", "--plain"],
    );
    request.timeout = None;
    // Go's exec.Cmd waits for the output pipes with no limit (WaitDelay 0).
    request.wait_delay = None;
    request
}

/// Go's `CollectSystemdTimers`: `exec.LookPath("systemctl")` first, and
/// no `systemctl` is no timers and no error; then the command, with Go's
/// text when it is refused, exits non-zero or prints too much.
pub(crate) fn collect_timers(policy: &CommandPolicy, zone: &Zone) -> Result<Vec<Entry>, String> {
    if !command_exists("systemctl", policy.search_path()) {
        return Ok(Vec::new());
    }
    let request = timers_request();
    let outcome = go_outcome(policy.run(&request), request.output_limit);
    match outcome.error {
        Some(error) => Err(error),
        None => Ok(parse_list_timers(&outcome.output, zone)),
    }
}

fn cron_entry(entry: Entry) -> CronEntry {
    CronEntry {
        source: entry.source.to_owned(),
        schedule: entry.schedule,
        command: entry.command,
        user: entry.user,
        next_run: entry.next_run,
        last_run: String::new(),
    }
}

/// Go's `LinuxCronBackend.ListEntries` and the reply: timers, then crontab
/// lines, and the errors of both, if any.
pub(crate) fn answer(
    request: CronListData,
    timers: Result<Vec<Entry>, String>,
    crontabs: (Vec<Entry>, Option<String>),
) -> CronListedData {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    match timers {
        Ok(timers) => entries.extend(timers),
        Err(error) => errors.push(format!("systemd timers: {error}")),
    }
    let (crontab_entries, crontab_error) = crontabs;
    entries.extend(crontab_entries);
    if let Some(error) = crontab_error {
        errors.push(format!("crontabs: {error}"));
    }
    let error = combine_errors(errors).unwrap_or_default();
    if !error.is_empty() {
        log::warn!("cron: failed to collect schedules: {error}");
    }
    CronListedData {
        request_id: request.request_id,
        entries: entries.into_iter().map(cron_entry).collect(),
        error,
    }
}
