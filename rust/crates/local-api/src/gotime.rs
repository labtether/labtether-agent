//! Go's time and duration text, as the Go agent's local pages write them:
//! `time.Time` JSON (RFC 3339 with up to nine fraction digits, trailing
//! zeros dropped, `Z` for a zero offset), `time.RFC3339` without a
//! fraction, `time.Parse(time.RFC3339, ...)` for the Hub's alert times, and
//! `time.Duration.String()` for whole seconds.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A moment and the zone offset it is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoTime {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub secs: i64,
    pub nanos: u32,
    /// Seconds east of UTC.
    pub offset: i32,
}

/// Seconds from 0001-01-01 to 1970-01-01: Go's zero `time.Time`.
const ZERO_SECS: i64 = -62_135_596_800;

impl GoTime {
    /// Go's zero time, `0001-01-01T00:00:00Z`.
    pub const ZERO: Self = Self {
        secs: ZERO_SECS,
        nanos: 0,
        offset: 0,
    };

    /// A system time in UTC.
    pub fn utc(time: SystemTime) -> Self {
        let (secs, nanos) = match time.duration_since(UNIX_EPOCH) {
            Ok(after) => (after.as_secs() as i64, after.subsec_nanos()),
            Err(before) => {
                let before = before.duration();
                let mut secs = -(before.as_secs() as i64);
                let mut nanos = before.subsec_nanos();
                if nanos > 0 {
                    secs -= 1;
                    nanos = 1_000_000_000 - nanos;
                }
                (secs, nanos)
            }
        };
        Self {
            secs,
            nanos,
            offset: 0,
        }
    }

    /// The system time for this moment (tests build views from fixtures).
    pub fn to_system(self) -> SystemTime {
        let nanos = Duration::from_nanos(u64::from(self.nanos));
        if self.secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(self.secs as u64) + nanos
        } else {
            UNIX_EPOCH - Duration::from_secs(self.secs.unsigned_abs()) + nanos
        }
    }

    pub fn is_zero(self) -> bool {
        self.secs == ZERO_SECS && self.nanos == 0
    }

    /// `time.Time` JSON text without the quotes; `None` for a year Go
    /// refuses to write (outside 0..=9999).
    pub fn rfc3339_nano(self) -> Option<String> {
        let mut text = self.rfc3339()?;
        if self.nanos > 0 {
            let fraction = format!("{:09}", self.nanos);
            let at = text.len() - zone_len(self.offset);
            text.insert_str(at, &format!(".{}", fraction.trim_end_matches('0')));
        }
        Some(text)
    }

    /// `time.RFC3339`: no fraction.
    pub fn rfc3339(self) -> Option<String> {
        let local = self.secs + i64::from(self.offset);
        let days = local.div_euclid(86_400);
        let of_day = local.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        if !(0..=9999).contains(&year) {
            return None;
        }
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{}",
            of_day / 3600,
            of_day % 3600 / 60,
            of_day % 60,
            zone(self.offset)
        ))
    }
}

fn zone(offset: i32) -> String {
    if offset == 0 {
        return "Z".to_owned();
    }
    let sign = if offset < 0 { '-' } else { '+' };
    let minutes = offset.unsigned_abs() / 60;
    format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

fn zone_len(offset: i32) -> usize {
    if offset == 0 { 1 } else { 6 }
}

/// Days since 1970-01-01 to a civil date (H. Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// A civil date to days since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

fn digits(text: &[u8], range: std::ops::Range<usize>) -> Option<u32> {
    let part = text.get(range)?;
    if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(part).ok()?.parse().ok()
}

/// `time.Parse(time.RFC3339, text)` for the forms the Hub writes:
/// `YYYY-MM-DDTHH:MM:SS`, an optional `.` or `,` fraction (digits past the
/// ninth are dropped, as in Go), then `Z` or `+hh:mm`/`-hh:mm`. The zone is
/// kept. Go's general parser also takes a few looser forms (a one-digit
/// hour); those read as `None` here, which the page shows as the zero time,
/// as Go shows any time it cannot read.
pub fn parse_rfc3339(text: &str) -> Option<GoTime> {
    let b = text.as_bytes();
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|&(at, want)| b.get(at) != Some(&want))
    {
        return None;
    }
    let year = i64::from(digits(b, 0..4)?);
    let (month, day) = (digits(b, 5..7)?, digits(b, 8..10)?);
    let (hour, minute, second) = (digits(b, 11..13)?, digits(b, 14..16)?, digits(b, 17..19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0u32;
    if matches!(b.get(at), Some(b'.' | b',')) {
        let start = at + 1;
        let end = start + b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
        if end == start {
            return None;
        }
        let kept = &text[start..end.min(start + 9)];
        nanos = format!("{kept:0<9}").parse().ok()?;
        at = end;
    }
    let offset = match &b[at..] {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (hours, minutes) = (digits(b, at + 1..at + 3)?, digits(b, at + 4..at + 6)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let value = (hours * 3600 + minutes * 60) as i32;
            if *sign == b'-' { -value } else { value }
        }
        _ => return None,
    };
    let local =
        days_from_civil(year, month, day) * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    Some(GoTime {
        secs: local - i64::from(offset),
        nanos,
        offset,
    })
}

/// `time.Duration.String()` for a whole number of seconds: `0s`, `45s`,
/// `3m2s`, `2h14m33s`, `1h0m0s`.
pub fn duration_text(secs: u64) -> String {
    let (hours, minutes, seconds) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if hours > 0 {
        format!("{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}
