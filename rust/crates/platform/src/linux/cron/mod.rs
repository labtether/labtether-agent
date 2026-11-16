//! The Scheduled jobs page's readers, ported from Go's
//! `internal/agentcore/backends/cron_handler.go`:
//!
//! - `timers`: the output of `systemctl list-timers --all --no-pager
//!   --plain` (the page starts the program; this parses its text);
//! - `crontab`: user crontabs in `/var/spool/cron/crontabs` and
//!   `/var/spool/cron`, then `/etc/cron.d`, then `/etc/crontab`, read
//!   directly with Go's rules for what is skipped and what is an error.
//!
//! Go lists timers first, then crontab lines, in that order.

pub mod crontab;
pub mod timers;

/// One scheduled job, as Go's `protocol.CronEntry` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `systemd-timer` or `crontab`.
    pub source: &'static str,
    pub schedule: String,
    pub command: String,
    pub user: String,
    /// RFC 3339, or empty.
    pub next_run: String,
}

/// Go's `combineScheduleErrors`: the non-empty messages, trimmed, joined
/// with `; `; `None` when there are none.
pub fn combine_errors(messages: impl IntoIterator<Item = String>) -> Option<String> {
    let kept: Vec<String> = messages
        .into_iter()
        .map(|m| m.trim().to_owned())
        .filter(|m| !m.is_empty())
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}
