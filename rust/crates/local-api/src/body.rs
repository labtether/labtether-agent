//! The JSON bodies of the local pages, field for field as the Go agent
//! writes them (`local_status.go` `StatusResponse`, `types.go`
//! `TelemetrySample` and `AgentInfo`, `servicehttp.go`), and the status
//! ETag and `If-None-Match` rules.

use data_encoding::HEXLOWER;
use labtether_agent_core::status::StatusView;
use sha2::{Digest, Sha256};

use crate::gojson::{NonFinite, Object, string};
use crate::gotime::{GoTime, duration_text, parse_rfc3339};

/// What the status page says about the local API itself.
#[derive(Debug, Clone)]
pub struct LocalFacts {
    pub port: String,
    pub bind_address: String,
    pub auth_enabled: bool,
}

/// Why a body could not be written. Go answers 500 for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// A metric is NaN or infinite.
    NonFinite,
    /// A time's year is outside 0..=9999.
    Year,
}

impl From<NonFinite> for BodyError {
    fn from(_: NonFinite) -> Self {
        Self::NonFinite
    }
}

fn time(out: &mut String, value: GoTime) -> Result<(), BodyError> {
    string(out, &value.rfc3339_nano().ok_or(BodyError::Year)?);
    Ok(())
}

/// The `metrics` object, also the `/agent/telemetry` body.
fn metrics(out: &mut String, view: &StatusView) -> Result<(), BodyError> {
    let sample = &view.latest.sample;
    let mut object = Object::start(out);
    object.str("asset_id", &view.asset_id);
    object.number("cpu_percent", sample.cpu_percent)?;
    object.number("memory_percent", sample.memory_percent)?;
    object.number("disk_percent", sample.disk_percent)?;
    object.number("net_rx_bytes", sample.net_rx_bytes)?;
    object.number("net_tx_bytes", sample.net_tx_bytes)?;
    object.number("net_rx_bytes_per_sec", sample.net_rx_bytes_per_sec)?;
    object.number("net_tx_bytes_per_sec", sample.net_tx_bytes_per_sec)?;
    if let Some(temperature) = sample.temp_celsius {
        object.number("temp_celsius", temperature)?;
    }
    time(
        object.key("collected_at"),
        GoTime::utc(view.latest.collected_at),
    )?;
    object.end();
    Ok(())
}

fn alerts(out: &mut String, view: &StatusView) -> Result<(), BodyError> {
    out.push('[');
    for (index, alert) in view.alerts.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let mut object = Object::start(out);
        object.str("id", &alert.id);
        object.str("severity", &alert.severity);
        object.str("title", &alert.title);
        object.str("summary", &alert.summary);
        object.str("state", &alert.state);
        let at = parse_rfc3339(&alert.timestamp).unwrap_or(GoTime::ZERO);
        time(object.key("timestamp"), at)?;
        object.end();
    }
    out.push(']');
    Ok(())
}

/// The `/agent/status` JSON with `uptime` as given (`None` omits it).
fn status_json(
    view: &StatusView,
    local: &LocalFacts,
    uptime: Option<&str>,
) -> Result<String, BodyError> {
    let mut out = String::with_capacity(1024);
    let connection = &view.connection;
    let mut object = Object::start(&mut out);
    object.str("agent_name", &view.agent_name);
    object.str("asset_id", &view.asset_id);
    object.str_nonempty("group_id", &view.group_id);
    object.str("port", &local.port);
    object.str_nonempty("device_fingerprint", &view.device_fingerprint);
    object.str_nonempty("device_key_algorithm", &view.device_key_algorithm);
    object.bool("connected", connection.connected);
    object.str("connection_state", connection.state.as_str());
    if let Some(at) = connection.disconnected_at {
        time(object.key("disconnected_at"), GoTime::utc(at))?;
    }
    object.str_nonempty("last_error", connection.last_error.as_deref().unwrap_or(""));
    object.str_nonempty(
        "last_error_reason",
        connection.last_error_reason.unwrap_or(""),
    );
    object.str_nonempty(
        "enrollment_error",
        connection.enrollment_error.as_deref().unwrap_or(""),
    );
    object.str_nonempty("uptime", uptime.unwrap_or(""));
    time(object.key("started_at"), GoTime::utc(view.started_at))?;
    metrics(object.key("metrics"), view)?;
    alerts(object.key("alerts"), view)?;
    object.str("agent_version", &view.agent_version);
    object.str_nonempty("local_bind_address", &local.bind_address);
    object.bool("local_auth_enabled", local.auth_enabled);
    object.bool("allow_insecure_transport", view.allow_insecure_transport);
    object.bool("update_available", false);
    object.end();
    Ok(out)
}

/// The status body (with Go's trailing newline) and its ETag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub body: String,
    pub etag: String,
}

/// Go's `statusHandler`: `uptime` is the time since start in whole
/// seconds; the ETag hashes the same JSON with `uptime` cut to whole
/// minutes, so a poller gets 304 until something other than the seconds
/// changes. A zero start time (never for a running agent) omits both.
pub fn status(view: &StatusView, local: &LocalFacts) -> Result<Status, BodyError> {
    let zero_start = GoTime::utc(view.started_at).is_zero();
    let seconds = view.uptime.as_secs();
    let exact = (!zero_start).then(|| duration_text(seconds));
    let bucket = (!zero_start).then(|| duration_text(seconds - seconds % 60));
    let tagged = status_json(view, local, bucket.as_deref())?;
    let etag = format!(
        "\"{}\"",
        HEXLOWER.encode(&Sha256::digest(tagged.as_bytes()))
    );
    let mut body = status_json(view, local, exact.as_deref())?;
    body.push('\n');
    Ok(Status { body, etag })
}

/// Go's `statusNormalizeETagToken`.
fn normalize_tag(value: &str) -> &str {
    let token = value.trim();
    let token = token
        .strip_prefix("W/")
        .or_else(|| token.strip_prefix("w/"))
        .unwrap_or(token);
    token.trim().trim_matches('"')
}

/// Go's `statusETagMatches`: any comma-separated entry that is `*` or the
/// same tag, weak or strong, quoted or not.
pub fn etag_matches(header: &str, etag: &str) -> bool {
    let wanted = normalize_tag(etag);
    !wanted.is_empty()
        && header.split(',').any(|part| {
            let part = part.trim();
            part == "*" || normalize_tag(part) == wanted
        })
}

/// The `/agent/telemetry` body.
pub fn telemetry(view: &StatusView) -> Result<String, BodyError> {
    let mut out = String::with_capacity(320);
    metrics(&mut out, view)?;
    out.push('\n');
    Ok(out)
}

/// Go's provider `AgentInfo` for this system.
pub fn agent_info() -> String {
    let (os, mode) = match std::env::consts::OS {
        "linux" => ("linux", "interactive-terminal-first"),
        "macos" => ("darwin", "launchd-helper"),
        other => (other, ""),
    };
    let mut out = String::new();
    let mut object = Object::start(&mut out);
    object.str("os", os);
    object.str("mode", mode);
    object.str("status", "active");
    object.end();
    out.push('\n');
    out
}

/// A body from string fields, keys sorted as Go writes a map.
pub fn sorted_map(fields: &mut [(&str, Value<'_>)]) -> String {
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::new();
    let mut object = Object::start(&mut out);
    for (key, value) in fields.iter() {
        match value {
            Value::Text(text) => object.str(key, text),
            Value::Bool(flag) => object.bool(key, *flag),
        }
    }
    object.end();
    out.push('\n');
    out
}

/// A map value.
pub enum Value<'a> {
    Text(&'a str),
    Bool(bool),
}

/// Go's `WriteError` body.
pub fn error(message: &str) -> String {
    sorted_map(&mut [("error", Value::Text(message))])
}
