//! `journalctl --output=json` lines, read as the Go agent's
//! `ParseJournalLine` reads them (`internal/agentcore/backends/journal.go`).
//!
//! Go decodes each line into five string fields with `encoding/json`, so a
//! line is skipped when it is not JSON, when one of those five fields holds
//! something other than a string or `null` (journalctl writes a field that
//! is not UTF-8, or that appears more than once, as an array), or when
//! `MESSAGE` is empty. Bytes that are not UTF-8 become U+FFFD one by one,
//! as Go's decoder does.

use serde::Deserialize;

use super::gotext::lossy;
use crate::linux::gotime::rfc3339;

/// Go's `scanner.Buffer(nil, 256*1024)` for journal output: a line of this
/// many bytes or more ends a query's read with `bufio.ErrTooLong`; the live
/// stream skips it.
pub const MAX_JOURNAL_LINE: usize = 256 * 1024;

/// One log entry: the fields of the protocol's `LogStreamData` that the
/// agent fills (Go leaves `asset_id` empty here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub timestamp: String,
    pub level: &'static str,
    pub message: String,
    pub source: String,
}

/// Go's `journalEntry`. A missing or `null` field is empty.
#[derive(Deserialize)]
struct Raw {
    #[serde(rename = "__REALTIME_TIMESTAMP", default)]
    realtime: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT", default)]
    unit: Option<String>,
    #[serde(rename = "PRIORITY", default)]
    priority: Option<String>,
    #[serde(rename = "MESSAGE", default)]
    message: Option<String>,
    #[serde(rename = "SYSLOG_IDENTIFIER", default)]
    identifier: Option<String>,
}

/// The entry in one line, or `None` where Go skips the line. `now` gives
/// the current Unix time, used when the timestamp is missing or not all
/// digits (Go's `time.Now()`).
pub fn parse_line(raw: &[u8], now: impl Fn() -> i64) -> Option<JournalEntry> {
    if raw.is_empty() {
        return None;
    }
    let text = lossy(raw);
    let fields: Raw = serde_json::from_str(&text).ok()?;
    let message = fields.message.unwrap_or_default();
    if message.is_empty() {
        return None;
    }
    let timestamp = timestamp(fields.realtime.as_deref().unwrap_or_default(), now);
    let mut source = fields.identifier.unwrap_or_default();
    if source.is_empty() {
        source = fields.unit.unwrap_or_default();
        // Go strips the suffix only from a name longer than it.
        if source.len() > 8 && source.ends_with(".service") {
            source.truncate(source.len() - 8);
        }
    }
    Some(JournalEntry {
        timestamp,
        level: level(fields.priority.as_deref().unwrap_or_default()),
        message,
        source,
    })
}

/// Go's `journalPriorityToLevel`: syslog priorities 0 to 7 by name.
pub fn level(priority: &str) -> &'static str {
    match priority {
        "0" | "1" | "2" | "3" => "error",
        "4" => "warning",
        "5" => "notice",
        "7" => "debug",
        _ => "info",
    }
}

/// Go's `journalTimestampToRFC3339`: microseconds since the epoch, in
/// decimal, as RFC 3339 in UTC to the second. Overflow wraps as Go's
/// `int64` does.
fn timestamp(micros: &str, now: impl Fn() -> i64) -> String {
    if micros.is_empty() || !micros.bytes().all(|b| b.is_ascii_digit()) {
        return rfc3339(now(), 0);
    }
    let value = micros.bytes().fold(0i64, |acc, digit| {
        acc.wrapping_mul(10).wrapping_add(i64::from(digit - b'0'))
    });
    // time.Unix(secs, nanos) normalizes a negative remainder downwards.
    rfc3339(value.div_euclid(1_000_000), 0)
}
