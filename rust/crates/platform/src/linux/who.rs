//! The Users page's parser: Go's `ParseUserSessionsOutput`
//! (`internal/agentcore/system/users.go`) over the output of `who`.
//!
//! Each line: name, terminal, login time, and an optional comment in
//! parentheses (the remote host, or `:0` for a local display). A line with
//! fewer than three words is skipped. The login time is read in the host's
//! zone (`time.Local`) and sent as RFC 3339 UTC:
//!
//! - `2026-11-16 12:15` (GNU `who` with a date locale, such as `C.UTF-8`
//!   or `en_AU.UTF-8`);
//! - `Nov 16 12:15` or `16 Nov 12:15` (GNU `who` in the C locale; macOS),
//!   which has no year: this year, or last year when that would be more
//!   than a day ahead;
//! - otherwise the words as printed; one word is sent as it is.
//!
//! A tmux pane (`(tmux(4649).%0)`) is not a remote host.

use super::gotime::{Civil, Layout, Zone, parse, rfc3339};
use crate::linux::tool_output::gotext::{lossy, scan_lines};

/// One signed-in session, as Go's `protocol.UserSession` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub username: String,
    pub terminal: String,
    pub remote_host: String,
    pub login_time: String,
}

/// Go's `ParseUserSessionsOutput`: `zone` is `time.Local`, `now` the
/// current Unix time (it dates a yearless login time).
pub fn parse_who(output: &[u8], zone: &Zone, now: i64) -> Vec<Session> {
    let mut sessions = Vec::new();
    for line in scan_lines(output).0 {
        let line = lossy(line);
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let mut login = &fields[2..];
        if let Some(last) = login.last()
            && last.starts_with('(')
            && last.ends_with(')')
        {
            login = &login[..login.len() - 1];
        }
        let login_time = match login.len() {
            0 => String::new(),
            1 => login[0].to_owned(),
            _ => login_time(login, zone, now),
        };
        sessions.push(Session {
            username: fields[0].to_owned(),
            terminal: fields[1].to_owned(),
            remote_host: remote_host(&fields),
            login_time,
        });
    }
    sessions
}

fn login_time(login: &[&str], zone: &Zone, now: i64) -> String {
    let iso = format!("{} {}", login[0], login[1]);
    if let Some(parsed) = parse(Layout::WhoIso, &iso) {
        return rfc3339(parsed.instant_in(zone), 0);
    }
    if let Some(unix) = month_day_time(login, zone, now) {
        return rfc3339(unix, 0);
    }
    login.join(" ")
}

/// Go's `parseBSDWhoTime`: `Jan 2 15:04` or `2 Jan 15:04`, dated this year
/// in `zone`, or last year when that is more than 24 hours after `now`.
fn month_day_time(login: &[&str], zone: &Zone, now: i64) -> Option<i64> {
    if login.len() < 3 {
        return None;
    }
    let text = login[..3].join(" ");
    let parsed = [Layout::WhoMonthDay, Layout::WhoDayMonth]
        .into_iter()
        .find_map(|layout| parse(layout, &text))?;
    let year = zone.civil(now).year;
    let mut unix = zone.date(
        year,
        parsed.month,
        parsed.day,
        parsed.hour,
        parsed.minute,
        0,
    );
    if unix > now + 24 * 3600 {
        // Go's AddDate(-1, 0, 0): the wall time of that instant, a year back.
        let Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
        } = zone.civil(unix);
        unix = zone.date(year - 1, month, day, hour, minute, second);
    }
    Some(unix)
}

/// Go's `whoRemoteHost`: the last word without its parentheses, unless it
/// is a tmux pane.
fn remote_host(fields: &[&str]) -> String {
    let Some(last) = fields.last() else {
        return String::new();
    };
    if last.len() < 3 || !last.starts_with('(') || !last.ends_with(')') {
        return String::new();
    }
    let comment = &last[1..last.len() - 1];
    if comment.starts_with("tmux(") {
        return String::new();
    }
    comment.to_owned()
}
