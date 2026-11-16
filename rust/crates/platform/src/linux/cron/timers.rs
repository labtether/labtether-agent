//! Go's parse of `systemctl list-timers --all --no-pager --plain`
//! (`CollectSystemdTimers`, `ParseSystemdTime`).
//!
//! Lines before the `NEXT ...` header are skipped; the first line after it
//! that starts with a digit (`11 timers listed.`) ends the list. Each row
//! with at least six words gives the second-to-last word as the schedule
//! (the timer unit) and the last as the command (the unit it starts), user
//! `root`. The next run is the first four words (`Mon 2026-11-16 12:33:43
//! AEDT`) unless they contain `n/a`; text that does not parse leaves it
//! empty, as does `-` (systemd 256 and later print that for no next run).

use super::Entry;
use crate::linux::gotime::{Layout, Zone, parse, rfc3339};
use crate::linux::tool_output::gotext::{lossy, scan_lines};

/// The rows of `systemctl list-timers` output. `local` is `time.Local`,
/// where Go looks up a zone abbreviation such as `AEDT`.
pub fn parse_list_timers(output: &[u8], local: &Zone) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut header_seen = false;
    for line in scan_lines(output).0 {
        let line = lossy(line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !header_seen {
            header_seen = line.starts_with("NEXT");
            continue;
        }
        if line.as_bytes()[0].is_ascii_digit() {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let next = fields[..4].join(" ");
        let next_run = if next.contains("n/a") {
            String::new()
        } else {
            systemd_time(&next, local).unwrap_or_default()
        };
        entries.push(Entry {
            source: "systemd-timer",
            schedule: fields[fields.len() - 2].to_owned(),
            command: fields[fields.len() - 1].to_owned(),
            user: "root".to_owned(),
            next_run,
        });
    }
    entries
}

/// Go's `ParseSystemdTime` then `Format(time.RFC3339)`: the first of four
/// layouts that parses, shown in the zone Go gives it.
pub fn systemd_time(text: &str, local: &Zone) -> Option<String> {
    [
        Layout::WeekdayAbbrev,
        Layout::WeekdayNumeric,
        Layout::Abbrev,
        Layout::Plain,
    ]
    .into_iter()
    .find_map(|layout| parse(layout, text))
    .map(|parsed| {
        let (unix, offset) = parsed.resolve(local);
        rfc3339(unix, offset)
    })
}
