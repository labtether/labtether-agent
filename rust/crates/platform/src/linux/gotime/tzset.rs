//! Go's `tzset`: the POSIX rule at the end of a TZif file (such as
//! `AEST-10AEDT,M10.1.0,M4.1.0/3`), used for times after the file's last
//! listed change. Ported line by line from Go's `time/zoneinfo.go`.

use super::{
    Civil, Lookup, OMEGA, SECONDS_PER_DAY, days_before, days_from_civil, days_in, is_leap,
};

const SECONDS_PER_HOUR: i64 = 3600;

#[derive(Debug, Clone, Copy)]
enum Rule {
    Julian {
        day: i64,
        time: i64,
    },
    DayOfYear {
        day: i64,
        time: i64,
    },
    MonthWeekDay {
        mon: i64,
        week: i64,
        day: i64,
        time: i64,
    },
}

/// The zone at `sec` by the rule `s`, the last listed change being at
/// `last_tx`. `None` when Go's parse fails.
pub(super) fn tzset(s: &str, last_tx: i64, sec: i64) -> Option<Lookup> {
    let (mut std_name, s) = tzset_name(s)?;
    let (std_offset, s) = tzset_offset(s)?;
    let mut std_offset = -std_offset;
    if s.is_empty() || s.starts_with(',') {
        return Some(Lookup {
            name: std_name.to_owned(),
            offset: std_offset,
            start: last_tx,
            end: OMEGA,
            is_dst: false,
        });
    }
    let (mut dst_name, mut s) = tzset_name(s)?;
    let mut dst_offset = if s.is_empty() || s.starts_with(',') {
        std_offset + SECONDS_PER_HOUR
    } else {
        let (offset, rest) = tzset_offset(s)?;
        s = rest;
        -offset
    };
    if s.is_empty() {
        s = ",M3.2.0,M11.1.0";
    }
    if !s.starts_with(',') && !s.starts_with(';') {
        return None;
    }
    let (start_rule, s) = tzset_rule(&s[1..])?;
    let s = s.strip_prefix(',')?;
    let (end_rule, s) = tzset_rule(s)?;
    if !s.is_empty() {
        return None;
    }

    let civil = Civil::from_unix(sec);
    let year = civil.year;
    let yday = sec.div_euclid(SECONDS_PER_DAY) - days_from_civil(year, 1, 1) + 1;
    let ysec = (yday - 1) * SECONDS_PER_DAY + sec % SECONDS_PER_DAY;
    let ystart = sec - ysec;

    let mut start_sec = rule_time(year, start_rule, std_offset);
    let mut end_sec = rule_time(year, end_rule, dst_offset);
    let (mut dst_is_dst, mut std_is_dst) = (true, false);
    if end_sec < start_sec {
        std::mem::swap(&mut start_sec, &mut end_sec);
        std::mem::swap(&mut std_name, &mut dst_name);
        std::mem::swap(&mut std_offset, &mut dst_offset);
        std::mem::swap(&mut std_is_dst, &mut dst_is_dst);
    }
    let found = |name: &str, offset, start, end, is_dst| Lookup {
        name: name.to_owned(),
        offset,
        start,
        end,
        is_dst,
    };
    Some(if ysec < start_sec {
        found(std_name, std_offset, ystart, start_sec + ystart, std_is_dst)
    } else if ysec >= end_sec {
        found(
            std_name,
            std_offset,
            end_sec + ystart,
            ystart + 365 * SECONDS_PER_DAY,
            std_is_dst,
        )
    } else {
        found(
            dst_name,
            dst_offset,
            start_sec + ystart,
            end_sec + ystart,
            dst_is_dst,
        )
    })
}

fn tzset_name(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    if let Some(quoted) = s.strip_prefix('<') {
        let end = quoted.find('>')?;
        return Some((&quoted[..end], &quoted[end + 1..]));
    }
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() || matches!(c, ',' | '-' | '+') {
            if i < 3 {
                return None;
            }
            return Some((&s[..i], &s[i..]));
        }
    }
    (s.len() >= 3).then_some((s, ""))
}

fn tzset_offset(s: &str) -> Option<(i64, &str)> {
    if s.is_empty() {
        return None;
    }
    let (neg, s) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let sign = |off: i64| if neg { -off } else { off };
    let (hours, s) = tzset_num(s, 0, 24 * 7)?;
    let mut off = hours * SECONDS_PER_HOUR;
    let Some(s) = s.strip_prefix(':') else {
        return Some((sign(off), s));
    };
    let (mins, s) = tzset_num(s, 0, 59)?;
    off += mins * 60;
    let Some(s) = s.strip_prefix(':') else {
        return Some((sign(off), s));
    };
    let (secs, s) = tzset_num(s, 0, 59)?;
    Some((sign(off + secs), s))
}

/// The date part of a rule, before its time is known.
enum When {
    Julian(i64),
    DayOfYear(i64),
    MonthWeekDay(i64, i64, i64),
}

fn tzset_rule(s: &str) -> Option<(Rule, &str)> {
    let first = *s.as_bytes().first()?;
    let (when, s) = if first == b'J' {
        let (day, s) = tzset_num(&s[1..], 1, 365)?;
        (When::Julian(day), s)
    } else if first == b'M' {
        let (mon, s) = tzset_num(&s[1..], 1, 12)?;
        let (week, s) = tzset_num(s.strip_prefix('.')?, 1, 5)?;
        let (day, s) = tzset_num(s.strip_prefix('.')?, 0, 6)?;
        (When::MonthWeekDay(mon, week, day), s)
    } else {
        let (day, s) = tzset_num(s, 0, 365)?;
        (When::DayOfYear(day), s)
    };
    let (time, s) = match s.strip_prefix('/') {
        None => (2 * SECONDS_PER_HOUR, s),
        Some(rest) => tzset_offset(rest)?,
    };
    let rule = match when {
        When::Julian(day) => Rule::Julian { day, time },
        When::DayOfYear(day) => Rule::DayOfYear { day, time },
        When::MonthWeekDay(mon, week, day) => Rule::MonthWeekDay {
            mon,
            week,
            day,
            time,
        },
    };
    Some((rule, s))
}

/// Go's `tzsetNum`: digits, each step checked against `max`, then `min`.
fn tzset_num(s: &str, min: i64, max: i64) -> Option<(i64, &str)> {
    if s.is_empty() {
        return None;
    }
    let mut num = 0;
    for (i, c) in s.char_indices() {
        let Some(digit) = c.to_digit(10) else {
            if i == 0 || num < min {
                return None;
            }
            return Some((num, &s[i..]));
        };
        num = num * 10 + i64::from(digit);
        if num > max {
            return None;
        }
    }
    (num >= min).then_some((num, ""))
}

/// Go's `tzruleTime`: seconds from the start of `year` to the change.
fn rule_time(year: i64, rule: Rule, off: i64) -> i64 {
    let (s, time) = match rule {
        Rule::Julian { day, time } => {
            let mut s = (day - 1) * SECONDS_PER_DAY;
            if is_leap(year) && day >= 60 {
                s += SECONDS_PER_DAY;
            }
            (s, time)
        }
        Rule::DayOfYear { day, time } => (day * SECONDS_PER_DAY, time),
        Rule::MonthWeekDay {
            mon,
            week,
            day,
            time,
        } => {
            // Zeller's congruence: the weekday of the first of `mon`.
            let m1 = (mon + 9) % 12 + 1;
            let yy0 = if mon <= 2 { year - 1 } else { year };
            let (yy1, yy2) = (yy0 / 100, yy0 % 100);
            let mut dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if dow < 0 {
                dow += 7;
            }
            let mut d = day - dow;
            if d < 0 {
                d += 7;
            }
            for _ in 1..week {
                if d + 7 >= days_in(mon, year) {
                    break;
                }
                d += 7;
            }
            d += days_before(mon);
            if is_leap(year) && mon > 2 {
                d += 1;
            }
            (d * SECONDS_PER_DAY, time)
        }
    };
    s + time - off
}
