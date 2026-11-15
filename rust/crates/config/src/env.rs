//! The process environment, captured once at start, and Go's value parsers.

use std::collections::HashMap;
use std::time::Duration;

/// A snapshot of the environment. The agent reads the process environment
/// once in `main`; nothing reads it again after start.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    vars: HashMap<String, String>,
}

impl Environment {
    /// Captures the current process environment.
    pub fn from_process() -> Self {
        Self::from_pairs(std::env::vars())
    }

    /// Builds an environment from name and value pairs (tests, wrappers).
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let vars = pairs
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        Self { vars }
    }

    /// The trimmed value, or `None` when unset or blank (Go's `envOrDefault`).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }

    /// The trimmed value, or `fallback` when unset or blank.
    pub fn get_or<'a>(&'a self, key: &str, fallback: &'a str) -> &'a str {
        self.get(key).unwrap_or(fallback)
    }

    /// Go's `parseBoolEnv`: an unset or unparsable value gives `fallback`.
    pub fn bool_or(&self, key: &str, fallback: bool) -> bool {
        self.get(key).and_then(parse_go_bool).unwrap_or(fallback)
    }
}

/// Go's `strconv.ParseBool`.
pub fn parse_go_bool(raw: &str) -> Option<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go's `parseDurationOrDefault`: whole seconds or a Go duration string,
/// clamped to `[min, max]`. Unparsable text gives `fallback`.
pub fn parse_duration_or(
    raw: Option<&str>,
    fallback: Duration,
    min: Duration,
    max: Duration,
) -> Duration {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return fallback;
    };
    if let Ok(seconds) = raw.parse::<i64>() {
        if seconds <= 0 {
            return min;
        }
        return Duration::from_secs(seconds.unsigned_abs()).clamp(min, max);
    }
    match parse_go_duration(raw) {
        Some(Signed::Negative) => min,
        Some(Signed::Positive(duration)) => duration.clamp(min, max),
        None => fallback,
    }
}

enum Signed {
    Positive(Duration),
    Negative,
}

/// A subset of Go's `time.ParseDuration`: an optional sign and one or more
/// decimal numbers with a unit (`ns`, `us`, `µs`, `ms`, `s`, `m`, `h`).
fn parse_go_duration(raw: &str) -> Option<Signed> {
    let (negative, mut rest) = match raw.as_bytes().first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    if rest == "0" {
        return Some(Signed::Positive(Duration::ZERO));
    }
    if rest.is_empty() {
        return None;
    }
    let mut total_nanos: f64 = 0.0;
    while !rest.is_empty() {
        let number_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let number: f64 = rest[..number_len].parse().ok()?;
        rest = &rest[number_len..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..unit_len] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return None,
        };
        rest = &rest[unit_len..];
        total_nanos += number * scale;
    }
    if !total_nanos.is_finite() || total_nanos > u64::MAX as f64 {
        return None;
    }
    let duration = Duration::from_nanos(total_nanos as u64);
    Some(if negative {
        Signed::Negative
    } else {
        Signed::Positive(duration)
    })
}
