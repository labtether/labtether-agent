//! Shared helpers for the local API tests: the contract copy, the code
//! rules of `codes.v1.json`, the shape comparison of the protocol's
//! `CompareStatusShape`, a fixture read back into a status view, and a
//! small HTTP client.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use labtether_agent_core::alerts::Alert;
use labtether_agent_core::link_status::{ConnectionState, ConnectionView};
use labtether_agent_core::status::{LatestSample, Sample, StatusView};
use labtether_agent_local_api::body::LocalFacts;
use labtether_agent_local_api::gotime::{GoTime, parse_rfc3339};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/localagent")
}

pub const FIXTURES: [&str; 10] = [
    "alerts-with-temperature",
    "auth-failed-enrollment-token-rejected",
    "auth-failed-token-rejected",
    "connected-token-persistence-failed",
    "connected",
    "connecting-transient-host-unreachable",
    "disconnected-no-transport",
    "enrollment-pending",
    "enrollment-refused-hub-words",
    "minimal-optional-fields-absent",
];

/// A fixture's text and its JSON.
pub fn fixture(name: &str) -> (String, Value) {
    let path = contract_dir().join(format!("fixtures/status/{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap();
    let value = serde_json::from_str(&text).unwrap();
    (text, value)
}

pub fn codes() -> Value {
    serde_json::from_str(&std::fs::read_to_string(contract_dir().join("codes.v1.json")).unwrap())
        .unwrap()
}

/// JSON text without the white space outside strings: Go's indented
/// output turned back into what `json.Marshal` wrote.
pub fn compact(text: &str) -> String {
    let (mut out, mut in_string, mut escaped) = (String::new(), false, false);
    for c in text.chars() {
        if in_string {
            out.push(c);
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_ascii_whitespace() {
            out.push(c);
        }
    }
    out
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The protocol's `CompareStatusShape`: same field names and JSON types at
/// every level; array items against the fixture's first item.
pub fn shape_differences(got: &Value, want: &Value, at: &str) -> Vec<String> {
    let mut out = Vec::new();
    if kind(got) != kind(want) {
        out.push(format!("{at}: got {}, want {}", kind(got), kind(want)));
        return out;
    }
    match (got, want) {
        (Value::Object(got), Value::Object(want)) => {
            for key in want.keys().filter(|k| !got.contains_key(*k)) {
                out.push(format!("{at}.{key}: missing"));
            }
            for key in got.keys().filter(|k| !want.contains_key(*k)) {
                out.push(format!("{at}.{key}: extra field"));
            }
            for (key, value) in got {
                if let Some(expected) = want.get(key) {
                    out.extend(shape_differences(value, expected, &format!("{at}.{key}")));
                }
            }
        }
        (Value::Array(got), Value::Array(want)) => match want.first() {
            Some(item) => {
                for (index, value) in got.iter().enumerate() {
                    out.extend(shape_differences(value, item, &format!("{at}[{index}]")));
                }
            }
            None if !got.is_empty() => out.push(format!("{at}: want an empty array")),
            None => {}
        },
        _ => {}
    }
    out
}

fn go_timestamp(text: &str) -> bool {
    let fraction_ok = match text.get(19..20) {
        Some(".") => {
            let digits: String = text[20..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            (1..=9).contains(&digits.len()) && !digits.ends_with('0')
        }
        _ => true,
    };
    fraction_ok && !text.contains(',') && parse_rfc3339(text).is_some()
}

fn go_uptime(text: &str) -> bool {
    if text == "0s" {
        return true;
    }
    let mut rest = text;
    for unit in ['h', 'm'] {
        if let Some((number, after)) = rest.split_once(unit)
            && !number.is_empty()
            && number.bytes().all(|b| b.is_ascii_digit())
        {
            rest = after;
        }
    }
    rest.len() > 1
        && rest.ends_with('s')
        && rest[..rest.len() - 1].bytes().all(|b| b.is_ascii_digit())
}

const TOP: [&str; 22] = [
    "agent_name",
    "asset_id",
    "group_id",
    "port",
    "device_fingerprint",
    "device_key_algorithm",
    "connected",
    "connection_state",
    "disconnected_at",
    "last_error",
    "last_error_reason",
    "enrollment_error",
    "uptime",
    "started_at",
    "metrics",
    "alerts",
    "agent_version",
    "local_bind_address",
    "local_auth_enabled",
    "allow_insecure_transport",
    "update_available",
    "latest_version",
];
const REQUIRED: [&str; 12] = [
    "agent_name",
    "asset_id",
    "port",
    "connected",
    "connection_state",
    "started_at",
    "metrics",
    "alerts",
    "agent_version",
    "local_auth_enabled",
    "allow_insecure_transport",
    "update_available",
];

fn listed(list: &Value, value: &str) -> bool {
    list.as_array()
        .is_some_and(|items| items.iter().any(|item| item == value))
}

/// The schema's closed sets and formats and the rules of `codes.v1.json`.
pub fn code_problems(body: &Value, codes: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let text = |key: &str| body.get(key).and_then(Value::as_str);
    for key in REQUIRED.iter().filter(|k| body.get(**k).is_none()) {
        out.push(format!("missing required field {key:?}"));
    }
    if let Some(object) = body.as_object() {
        for key in object.keys().filter(|k| !TOP.contains(&k.as_str())) {
            out.push(format!("field {key:?} is not in the schema"));
        }
    }
    let state = text("connection_state").unwrap_or("");
    let last_error = text("last_error").unwrap_or("");
    let reason = text("last_error_reason").unwrap_or("");
    if !listed(&codes["connection_states"], state) {
        out.push(format!("connection_state {state:?} is not in the set"));
    }
    if !listed(&codes["last_error_by_state"][state], last_error) {
        out.push(format!(
            "last_error {last_error:?} does not go with {state:?}"
        ));
    }
    if !listed(
        &codes["last_error_reason_by_last_error"][last_error],
        reason,
    ) {
        out.push(format!(
            "last_error_reason {reason:?} does not go with {last_error:?}"
        ));
    }
    for key in [
        "last_error",
        "last_error_reason",
        "enrollment_error",
        "group_id",
        "uptime",
    ] {
        if text(key) == Some("") {
            out.push(format!("{key} is sent empty"));
        }
    }
    let connected = body["connected"].as_bool().unwrap_or(false);
    if connected != (state == codes["connected_true_only_in_state"]) {
        out.push(format!("connected {connected} with {state:?}"));
    }
    if connected && body.get("enrollment_error").is_some() {
        out.push("enrollment_error while connected".into());
    }
    if let Some(words) = text("enrollment_error")
        && (words.chars().count() > 300 || words.chars().any(char::is_control))
    {
        out.push("enrollment_error is not one line of at most 300 characters".into());
    }
    if body.get("disconnected_at").is_some()
        && (listed(&codes["absent_disconnected_at_states"], state)
            || listed(&codes["absent_disconnected_at_last_errors"], last_error))
    {
        out.push(format!("disconnected_at with {state:?} / {last_error:?}"));
    }
    let mut times = vec![
        body.get("started_at"),
        body.get("disconnected_at"),
        body["metrics"].get("collected_at"),
    ];
    if let Some(alerts) = body["alerts"].as_array() {
        if alerts.len() > 20 {
            out.push("more than 20 alerts".into());
        }
        times.extend(alerts.iter().map(|alert| alert.get("timestamp")));
    }
    for time in times.into_iter().flatten() {
        if !time.as_str().is_some_and(go_timestamp) {
            out.push(format!("{time} is not Go time text"));
        }
    }
    if let Some(uptime) = text("uptime").filter(|u| !go_uptime(u)) {
        out.push(format!("uptime {uptime:?} is not Go duration text"));
    }
    if !text("port")
        .is_some_and(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
    {
        out.push("port is not 1 to 5 digits".into());
    }
    for key in ["cpu_percent", "memory_percent", "disk_percent"] {
        if !body["metrics"][key]
            .as_f64()
            .is_some_and(|v| (0.0..=100.0).contains(&v))
        {
            out.push(format!("metrics.{key} is not a percentage"));
        }
    }
    out
}

fn reason_code(text: &str) -> &'static str {
    [
        "name_lookup_failed",
        "connection_refused",
        "host_unreachable",
        "timed_out",
        "certificate_untrusted",
        "token_rejected",
    ]
    .into_iter()
    .find(|code| *code == text)
    .unwrap_or_else(|| panic!("unknown reason {text}"))
}

fn duration(text: &str) -> Duration {
    let mut seconds = 0;
    let mut number = 0;
    for c in text.chars() {
        match c {
            '0'..='9' => number = number * 10 + u64::from(c as u8 - b'0'),
            'h' => (seconds, number) = (seconds + number * 3600, 0),
            'm' => (seconds, number) = (seconds + number * 60, 0),
            's' => (seconds, number) = (seconds + number, 0),
            _ => panic!("bad duration {text}"),
        }
    }
    Duration::from_secs(seconds)
}

/// A fixture read back into the view and facts the body is built from.
pub fn view_from_fixture(v: &Value) -> (StatusView, LocalFacts) {
    let s = |key: &str| v[key].as_str().unwrap_or("").to_owned();
    let time = |text: &str| parse_rfc3339(text).unwrap().to_system();
    let m = &v["metrics"];
    let f = |key: &str| m[key].as_f64().unwrap();
    let state = match v["connection_state"].as_str().unwrap() {
        "connected" => ConnectionState::Connected,
        "connecting" => ConnectionState::Connecting,
        "auth_failed" => ConnectionState::AuthFailed,
        _ => ConnectionState::Disconnected,
    };
    let alerts = v["alerts"].as_array().unwrap().iter().map(|a| Alert {
        id: a["id"].as_str().unwrap().into(),
        severity: a["severity"].as_str().unwrap().into(),
        title: a["title"].as_str().unwrap().into(),
        summary: a["summary"].as_str().unwrap().into(),
        state: a["state"].as_str().unwrap().into(),
        timestamp: a["timestamp"].as_str().unwrap().into(),
    });
    let view = StatusView {
        agent_name: s("agent_name"),
        asset_id: s("asset_id"),
        group_id: s("group_id"),
        device_fingerprint: s("device_fingerprint"),
        device_key_algorithm: s("device_key_algorithm"),
        connection: ConnectionView {
            connected: v["connected"].as_bool().unwrap(),
            state,
            last_error: v["last_error"].as_str().map(str::to_owned),
            last_error_reason: v["last_error_reason"].as_str().map(reason_code),
            disconnected_at: v["disconnected_at"].as_str().map(time),
            enrollment_error: v["enrollment_error"].as_str().map(str::to_owned),
        },
        started_at: time(v["started_at"].as_str().unwrap()),
        uptime: v["uptime"].as_str().map(duration).unwrap_or_default(),
        latest: LatestSample {
            sample: Sample {
                cpu_percent: f("cpu_percent"),
                memory_percent: f("memory_percent"),
                disk_percent: f("disk_percent"),
                net_rx_bytes: f("net_rx_bytes"),
                net_tx_bytes: f("net_tx_bytes"),
                net_rx_bytes_per_sec: f("net_rx_bytes_per_sec"),
                net_tx_bytes_per_sec: f("net_tx_bytes_per_sec"),
                temp_celsius: m["temp_celsius"].as_f64(),
            },
            collected_at: time(m["collected_at"].as_str().unwrap()),
        },
        alerts: alerts.collect(),
        agent_version: s("agent_version"),
        allow_insecure_transport: v["allow_insecure_transport"].as_bool().unwrap(),
    };
    let local = LocalFacts {
        port: s("port"),
        bind_address: s("local_bind_address"),
        auth_enabled: v["local_auth_enabled"].as_bool().unwrap(),
    };
    (view, local)
}

/// Go's zero time as a system time, for views built by hand.
pub fn zero_time() -> std::time::SystemTime {
    GoTime::ZERO.to_system()
}

/// One HTTP answer.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Sends `raw` (a whole request) and reads the answer until the server
/// closes the connection.
pub async fn exchange(port: u16, raw: &str) -> std::io::Result<Answer> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(raw.as_bytes()).await?;
    let mut data = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut data))
        .await
        .map_err(|_| std::io::Error::other("no answer within 10 s"))??;
    let text = String::from_utf8_lossy(&data).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Ok(Answer {
        status,
        headers,
        body: body.to_owned(),
    })
}

/// `GET path` with extra header lines, on a closing connection.
pub async fn get(port: u16, path: &str, headers: &[(&str, &str)]) -> std::io::Result<Answer> {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    exchange(port, &raw).await
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
