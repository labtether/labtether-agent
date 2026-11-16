//! The parts of Go's `time` package the Users and Scheduled jobs pages
//! depend on, ported so their times match the Go agent's on any host:
//!
//! - `time.Local`: `TZ`, else `/etc/localtime`, read from TZif files with
//!   Go's rules (`tzif.rs`), including the POSIX rule at the end of the
//!   file for times after the last listed change (`tzset.rs`);
//! - a zone's offset at an instant (`Location.lookup`), a zone found by its
//!   abbreviation (`lookupName`), and a wall-clock time turned into an
//!   instant (`time.Date`, with Go's choice in a gap or an overlap);
//! - `time.Parse` for the few layouts the pages use (`parse.rs`);
//! - RFC 3339 text as `Time.Format(time.RFC3339)` writes it.
//!
//! Go keeps `time.Local` for the life of the process; the pages load it
//! once at start.

mod parse;
mod tzif;
mod tzset;

pub use parse::{Layout, ParsedTime, ZonePart, parse};
pub use tzif::{from_tzif, local_zone, local_zone_with};

/// Go's `alpha` and `omega`: the start and end of time.
const ALPHA: i64 = i64::MIN;
const OMEGA: i64 = i64::MAX;
const SECONDS_PER_DAY: i64 = 86_400;

/// One local time type of a zone: its abbreviation, offset east of UTC in
/// seconds and whether it is daylight time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneType {
    pub name: String,
    pub offset: i64,
    pub is_dst: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Transition {
    pub when: i64,
    pub index: usize,
}

/// A time zone as Go's `*time.Location` holds it. No types means UTC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Zone {
    pub(crate) types: Vec<ZoneType>,
    pub(crate) transitions: Vec<Transition>,
    /// The POSIX rule after the last transition (the TZif footer).
    pub(crate) extend: String,
}

/// What `lookup` returns: the zone in effect and the span it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub name: String,
    pub offset: i64,
    pub start: i64,
    pub end: i64,
    pub is_dst: bool,
}

impl Zone {
    /// Go's `time.UTC`.
    pub fn utc() -> Self {
        Self::default()
    }

    /// Go's `Location.lookup`: the zone in effect at `sec` (Unix seconds).
    pub fn lookup(&self, sec: i64) -> Lookup {
        if self.types.is_empty() {
            return Lookup {
                name: "UTC".into(),
                offset: 0,
                start: ALPHA,
                end: OMEGA,
                is_dst: false,
            };
        }
        let tx = &self.transitions;
        if tx.is_empty() || sec < tx[0].when {
            let zone = &self.types[self.first_zone()];
            return Lookup {
                name: zone.name.clone(),
                offset: zone.offset,
                start: ALPHA,
                end: tx.first().map_or(OMEGA, |t| t.when),
                is_dst: zone.is_dst,
            };
        }
        let (mut lo, mut hi, mut end) = (0, tx.len(), OMEGA);
        while hi - lo > 1 {
            let m = (lo + hi) / 2;
            if sec < tx[m].when {
                end = tx[m].when;
                hi = m;
            } else {
                lo = m;
            }
        }
        let zone = &self.types[tx[lo].index];
        let start = tx[lo].when;
        if lo == tx.len() - 1
            && !self.extend.is_empty()
            && let Some(found) = tzset::tzset(&self.extend, start, sec)
        {
            return found;
        }
        Lookup {
            name: zone.name.clone(),
            offset: zone.offset,
            start,
            end,
            is_dst: zone.is_dst,
        }
    }

    /// Go's `lookupFirstZone`: the type for times before the first change.
    fn first_zone(&self) -> usize {
        let used = |i: usize| self.transitions.iter().any(|t| t.index == i);
        if !used(0) {
            return 0;
        }
        if let Some(first) = self.transitions.first()
            && self.types[first.index].is_dst
        {
            for zi in (0..first.index).rev() {
                if !self.types[zi].is_dst {
                    return zi;
                }
            }
        }
        self.types.iter().position(|z| !z.is_dst).unwrap_or(0)
    }

    /// Go's `lookupName`: the offset of the zone type called `name`,
    /// preferring one in effect at `unix` (the wall time read as UTC).
    pub fn lookup_name(&self, name: &str, unix: i64) -> Option<i64> {
        for zone in self.types.iter().filter(|z| z.name == name) {
            let found = self.lookup(unix - zone.offset);
            if found.name == zone.name {
                return Some(found.offset);
            }
        }
        self.types.iter().find(|z| z.name == name).map(|z| z.offset)
    }

    /// Go's `time.Date(year, month, day, hour, min, sec, 0, zone)` as Unix
    /// seconds. A wall time in a gap or an overlap gets Go's answer.
    pub fn date(&self, year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
        let unix =
            days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + min * 60 + sec;
        let found = self.lookup(unix);
        let mut offset = found.offset;
        if offset != 0 {
            let utc = unix - offset;
            if utc < found.start || utc >= found.end {
                offset = self.lookup(utc).offset;
            }
            return unix - offset;
        }
        unix
    }

    /// The wall clock at `unix` in this zone: `(year, month, day, hour,
    /// minute, second)`.
    pub fn civil(&self, unix: i64) -> Civil {
        Civil::from_unix(unix + self.lookup(unix).offset)
    }
}

/// A wall-clock time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
}

impl Civil {
    pub fn from_unix(unix: i64) -> Self {
        let (year, month, day) = civil_from_days(unix.div_euclid(SECONDS_PER_DAY));
        let rem = unix.rem_euclid(SECONDS_PER_DAY);
        Self {
            year,
            month,
            day,
            hour: rem / 3600,
            minute: rem % 3600 / 60,
            second: rem % 60,
        }
    }
}

/// `Time.Format(time.RFC3339)` for the instant `unix` shown with `offset`
/// (seconds east of UTC): `Z` for offset 0, else `+hh:mm`.
pub fn rfc3339(unix: i64, offset: i64) -> String {
    let c = Civil::from_unix(unix + offset);
    let date = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    );
    if offset == 0 {
        return date + "Z";
    }
    let minutes = offset / 60;
    let sign = if minutes < 0 { '-' } else { '+' };
    let minutes = minutes.abs();
    format!("{date}{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

pub fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Go's `daysIn`.
pub fn days_in(month: i64, year: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days before the first of `month` in a common year (Go's `daysBefore`).
pub(crate) fn days_before(month: i64) -> i64 {
    [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365][(month - 1) as usize]
}

/// Days since 1970-01-01 of a proleptic Gregorian date. A day past the end
/// of its month rolls into the next, as in Go's `Date`.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
