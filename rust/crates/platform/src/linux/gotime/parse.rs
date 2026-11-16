//! Go's `time.Parse` and `time.ParseInLocation` for the layouts the Go
//! agent uses on these pages, with Go's rules for each layout element:
//! month and weekday names in any letter case, one- or two-digit day and
//! hour, two-digit month, minute and second, a fraction after the seconds
//! accepted, runs of spaces matching one, the day checked against its month
//! (with year 0 when the layout has none, a leap year), and no extra text.

use super::{Zone, days_in};

/// The layouts these pages parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `2006-01-02 15:04`: `who` with a date locale.
    WhoIso,
    /// `Jan 2 15:04`: `who` in the C locale (and macOS).
    WhoMonthDay,
    /// `2 Jan 15:04`: macOS `who` in some locales.
    WhoDayMonth,
    /// `Mon 2006-01-02 15:04:05 MST`: `systemctl list-timers`.
    WeekdayAbbrev,
    /// `Mon 2006-01-02 15:04:05 -0700`.
    WeekdayNumeric,
    /// `2006-01-02 15:04:05 MST`.
    Abbrev,
    /// `2006-01-02 15:04:05`.
    Plain,
}

#[derive(Debug, Clone, Copy)]
enum Part {
    Lit(&'static str),
    WeekDay,
    MonthName,
    Year,
    Month,
    Day,
    ZeroDay,
    Hour,
    Minute,
    Second,
    ZoneName,
    ZoneNumeric,
}

use Part::*;

impl Layout {
    fn parts(self) -> &'static [Part] {
        const DATE: [Part; 5] = [Year, Lit("-"), Month, Lit("-"), ZeroDay];
        const TIME: [Part; 5] = [Hour, Lit(":"), Minute, Lit(":"), Second];
        match self {
            Self::WhoIso => &[
                Year,
                Lit("-"),
                Month,
                Lit("-"),
                ZeroDay,
                Lit(" "),
                Hour,
                Lit(":"),
                Minute,
            ],
            Self::WhoMonthDay => &[MonthName, Lit(" "), Day, Lit(" "), Hour, Lit(":"), Minute],
            Self::WhoDayMonth => &[Day, Lit(" "), MonthName, Lit(" "), Hour, Lit(":"), Minute],
            Self::WeekdayAbbrev => &[
                WeekDay,
                Lit(" "),
                DATE[0],
                DATE[1],
                DATE[2],
                DATE[3],
                DATE[4],
                Lit(" "),
                TIME[0],
                TIME[1],
                TIME[2],
                TIME[3],
                TIME[4],
                Lit(" "),
                ZoneName,
            ],
            Self::WeekdayNumeric => &[
                WeekDay,
                Lit(" "),
                DATE[0],
                DATE[1],
                DATE[2],
                DATE[3],
                DATE[4],
                Lit(" "),
                TIME[0],
                TIME[1],
                TIME[2],
                TIME[3],
                TIME[4],
                Lit(" "),
                ZoneNumeric,
            ],
            Self::Abbrev => &[
                DATE[0],
                DATE[1],
                DATE[2],
                DATE[3],
                DATE[4],
                Lit(" "),
                TIME[0],
                TIME[1],
                TIME[2],
                TIME[3],
                TIME[4],
                Lit(" "),
                ZoneName,
            ],
            Self::Plain => &[
                DATE[0],
                DATE[1],
                DATE[2],
                DATE[3],
                DATE[4],
                Lit(" "),
                TIME[0],
                TIME[1],
                TIME[2],
                TIME[3],
                TIME[4],
            ],
        }
    }
}

/// The zone part of a parsed time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZonePart {
    None,
    Utc,
    /// An abbreviation such as `AEDT`, `GMT+3` or `+11`.
    Name(String),
    /// A numeric offset such as `-0700`, in seconds east of UTC.
    Offset(i64),
}

/// The fields Go's parse read, before a location is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTime {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    pub zone: ZonePart,
}

impl ParsedTime {
    /// `ParseInLocation` with no zone in the layout: the instant of this
    /// wall time in `zone`.
    pub fn instant_in(&self, zone: &Zone) -> i64 {
        zone.date(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
    }

    /// `time.Parse` (default UTC, abbreviations looked up in `local`): the
    /// instant and the offset `Format` shows it with.
    pub fn resolve(&self, local: &Zone) -> (i64, i64) {
        let utc = Zone::utc().date(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        );
        match &self.zone {
            ZonePart::None | ZonePart::Utc => (utc, 0),
            ZonePart::Offset(offset) => (utc - offset, *offset),
            ZonePart::Name(name) => match local.lookup_name(name, utc) {
                Some(offset) => {
                    let unix = utc - offset;
                    (unix, local.lookup(unix).offset)
                }
                // Go records a made-up zone with that name and offset 0
                // (GMT+n: n hours) without moving the instant.
                None => {
                    let hours = name
                        .strip_prefix("GMT")
                        .filter(|rest| !rest.is_empty())
                        .and_then(|rest| rest.parse::<i64>().ok())
                        .unwrap_or(0);
                    (utc, hours * 3600)
                }
            },
        }
    }
}

fn cut_space(v: &[u8]) -> &[u8] {
    let n = v.iter().take_while(|&&b| b == b' ').count();
    &v[n..]
}

/// Go's `skip`: the literal, with a run of spaces matching any run.
fn skip<'a>(mut value: &'a [u8], prefix: &str) -> Option<&'a [u8]> {
    let mut prefix = prefix.as_bytes();
    while let Some(&p) = prefix.first() {
        if p == b' ' {
            if value.first().is_some_and(|&b| b != b' ') {
                return None;
            }
            prefix = cut_space(prefix);
            value = cut_space(value);
            continue;
        }
        if value.first() != Some(&p) {
            return None;
        }
        prefix = &prefix[1..];
        value = &value[1..];
    }
    Some(value)
}

fn digit(v: &[u8], i: usize) -> Option<i64> {
    v.get(i)
        .filter(|b| b.is_ascii_digit())
        .map(|b| i64::from(b - b'0'))
}

/// Go's `getnum`: one or two digits (two when `fixed`).
fn getnum(v: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    let first = digit(v, 0)?;
    match digit(v, 1) {
        Some(second) => Some((first * 10 + second, &v[2..])),
        None if fixed => None,
        None => Some((first, &v[1..])),
    }
}

/// Go's `lookup` over a name table, ignoring ASCII letter case.
fn lookup<'a>(table: &[&str], v: &'a [u8]) -> Option<(usize, &'a [u8])> {
    table.iter().enumerate().find_map(|(i, name)| {
        let n = name.len();
        (v.len() >= n && v[..n].eq_ignore_ascii_case(name.as_bytes())).then(|| (i, &v[n..]))
    })
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Go's `parseSignedOffset`: a sign and a number up to 23; its length.
fn signed_offset_len(v: &[u8]) -> usize {
    if !matches!(v.first(), Some(b'+' | b'-')) {
        return 0;
    }
    let digits = v[1..].iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return 0;
    }
    match std::str::from_utf8(&v[1..1 + digits])
        .ok()
        .and_then(|d| d.parse::<u64>().ok())
    {
        Some(x) if x <= 23 => 1 + digits,
        _ => 0,
    }
}

/// Go's `parseTimeZone`: the length of the abbreviation at the start.
fn time_zone_len(v: &[u8]) -> Option<usize> {
    if v.len() < 3 {
        return None;
    }
    if v.len() >= 4 && (&v[..4] == b"ChST" || &v[..4] == b"MeST") {
        return Some(4);
    }
    if &v[..3] == b"GMT" {
        return Some(3 + signed_offset_len(&v[3..]));
    }
    if v[0] == b'+' || v[0] == b'-' {
        let n = signed_offset_len(v);
        return (n > 0).then_some(n);
    }
    let upper = v
        .iter()
        .take(6)
        .take_while(|b| b.is_ascii_uppercase())
        .count();
    match upper {
        3 => Some(3),
        4 if v[3] == b'T' || &v[..4] == b"WITA" => Some(4),
        5 if v[4] == b'T' => Some(5),
        _ => None,
    }
}

/// Go's parse of `value` by `layout`; `None` where Go returns an error.
pub fn parse(layout: Layout, value: &str) -> Option<ParsedTime> {
    let mut v = value.as_bytes();
    let (mut year, mut month, mut day) = (0, -1, -1);
    let (mut hour, mut minute, mut second) = (0, 0, 0);
    let mut zone = ZonePart::None;
    for part in layout.parts() {
        v = match *part {
            Lit(text) => skip(v, text)?,
            WeekDay => lookup(&DAYS, v)?.1,
            MonthName => {
                let (m, rest) = lookup(&MONTHS, v)?;
                month = m as i64 + 1;
                rest
            }
            Year => {
                if v.len() < 4 || !v[..4].iter().all(u8::is_ascii_digit) {
                    return None;
                }
                year = v[..4].iter().fold(0, |n, b| n * 10 + i64::from(b - b'0'));
                &v[4..]
            }
            Month => {
                let (m, rest) = getnum(v, true)?;
                if !(1..=12).contains(&m) {
                    return None;
                }
                month = m;
                rest
            }
            Day | ZeroDay => {
                let (d, rest) = getnum(v, matches!(part, ZeroDay))?;
                day = d;
                rest
            }
            Hour => {
                let (h, rest) = getnum(v, false)?;
                if h >= 24 {
                    return None;
                }
                hour = h;
                rest
            }
            Minute => {
                let (m, rest) = getnum(v, true)?;
                if m >= 60 {
                    return None;
                }
                minute = m;
                rest
            }
            Second => {
                let (s, mut rest) = getnum(v, true)?;
                if s >= 60 {
                    return None;
                }
                second = s;
                // A fraction the layout does not ask for is read and dropped.
                if rest.len() >= 2 && matches!(rest[0], b'.' | b',') && rest[1].is_ascii_digit() {
                    let n = 1 + rest[1..].iter().take_while(|b| b.is_ascii_digit()).count();
                    rest = &rest[n..];
                }
                rest
            }
            ZoneName => {
                if v.starts_with(b"UTC") {
                    zone = ZonePart::Utc;
                    &v[3..]
                } else {
                    let n = time_zone_len(v)?;
                    zone = ZonePart::Name(String::from_utf8_lossy(&v[..n]).into_owned());
                    &v[n..]
                }
            }
            ZoneNumeric => {
                if v.len() < 5 {
                    return None;
                }
                let (hr, _) = getnum(&v[1..3], true)?;
                let (mm, _) = getnum(&v[3..5], true)?;
                if hr > 24 || mm > 60 {
                    return None;
                }
                let offset = (hr * 60 + mm) * 60;
                zone = ZonePart::Offset(match v[0] {
                    b'+' => offset,
                    b'-' => -offset,
                    _ => return None,
                });
                &v[5..]
            }
        };
    }
    if !v.is_empty() {
        return None;
    }
    let month = if month < 0 { 1 } else { month };
    let day = if day < 0 { 1 } else { day };
    if day < 1 || day > days_in(month, year) {
        return None;
    }
    Some(ParsedTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        zone,
    })
}
