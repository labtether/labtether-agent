//! The `/metrics` page: Go's `RenderPrometheus` (`metrics.go`), the same
//! seven families, names, help text, types and number formats.

use std::fmt::Write as _;

use labtether_agent_core::status::StatusView;

use crate::gotime::GoTime;

/// Go's `%q` for a label value (`strconv.Quote`): `"` and `\` escaped,
/// control characters as Go writes them, other characters kept.
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go's `%.<precision>f`, with Go's text for NaN and the infinities.
fn fixed(value: f64, precision: usize) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value.is_infinite() {
        if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        format!("{value:.precision$}")
    }
}

fn family(out: &mut String, name: &str, help: &str, kind: &str, label: &str, value: &str) {
    let _ = write!(
        out,
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name}{{{label}}} {value}\n"
    );
}

/// The page text.
pub fn render(view: &StatusView) -> String {
    let sample = &view.latest.sample;
    let label = format!("asset_id={}", quote(&view.asset_id));
    let mut out = String::with_capacity(1200);
    let prefix = "labtether_agent_";
    let rows = [
        (
            "cpu_usage_percent",
            "CPU usage percentage.",
            "gauge",
            fixed(sample.cpu_percent, 4),
        ),
        (
            "memory_used_percent",
            "Memory usage percentage.",
            "gauge",
            fixed(sample.memory_percent, 4),
        ),
        (
            "disk_used_percent",
            "Disk usage percentage.",
            "gauge",
            fixed(sample.disk_percent, 4),
        ),
        (
            "network_rx_bytes_total",
            "Total received network bytes.",
            "counter",
            fixed(sample.net_rx_bytes, 0),
        ),
        (
            "network_tx_bytes_total",
            "Total transmitted network bytes.",
            "counter",
            fixed(sample.net_tx_bytes, 0),
        ),
    ];
    for (name, help, kind, value) in rows {
        family(
            &mut out,
            &format!("{prefix}{name}"),
            help,
            kind,
            &label,
            &value,
        );
    }
    if let Some(temperature) = sample.temp_celsius {
        family(
            &mut out,
            "labtether_agent_temp_celsius",
            "Host temperature in celsius when available.",
            "gauge",
            &label,
            &fixed(temperature, 4),
        );
    }
    family(
        &mut out,
        "labtether_agent_scrape_timestamp_seconds",
        "Last collector update timestamp in unix seconds.",
        "gauge",
        &label,
        &GoTime::utc(view.latest.collected_at).secs.to_string(),
    );
    out
}
