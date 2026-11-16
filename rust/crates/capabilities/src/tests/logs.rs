//! The logs page's query with fake `journalctl` programs, through the real
//! command rules, against the Go agent's own replies to the same cases
//! (`testdata/go/journal-query-*.json`, made by the A2d step's oracle on
//! the lab VM with the same script bodies, `scripts/oracle/run.sh`). The
//! long lines are built here; Go's answer for the 256 KiB−1 one is kept
//! with its message written as `"262129 × a"` (see [`compact`]).

use std::time::Duration;

use labtether_agent_core::Features;
use labtether_protocol::{JournalQueryData, MSG_JOURNAL_ENTRIES, MSG_JOURNAL_QUERY, Message};
use serde_json::{Value, json};

use super::fakebin::{FakeBin, serial};
use crate::Commands;
use crate::logs::query::{answer, query_args};

const FIXTURE: &[u8] = include_bytes!("../../../platform/testdata/journal-lines.jsonl");
const GO_LINES: &str = include_str!("../../../platform/testdata/go/journal-lines.json");
const REC: &str = "printf \"%s\\n\" \"$@\" > \"$W/args\"";

/// Go's reply to each case: `(name, script body, request)`.
const CASES: &[(&str, &str, &str)] = &[
    (
        "fixture",
        "printf \"%s\\n\" \"$@\" > \"$W/args\"\n/bin/cat \"$W/fixture.jsonl\"",
        r#"{"request_id":"q1"}"#,
    ),
    (
        "options",
        REC,
        r#"{"request_id":"q2","since":" 1h ago ","until":"now","unit":"--rotate","priority":"err","search":"a b","limit":5000}"#,
    ),
    (
        "long-ok",
        "/bin/cat \"$W/long-ok.jsonl\"",
        r#"{"request_id":"q3","limit":7}"#,
    ),
    (
        "long-bad",
        "/bin/cat \"$W/long-bad.jsonl\"",
        r#"{"request_id":"q3","limit":7}"#,
    ),
    (
        "stderr",
        "echo \"Failed to add match 'x': Invalid argument\" >&2; exit 1",
        r#"{"request_id":"q3","limit":7}"#,
    ),
    ("silent", "exit 1", r#"{"request_id":"q3","limit":7}"#),
    (
        "signal",
        "kill -TERM $$",
        r#"{"request_id":"q3","limit":7}"#,
    ),
    (
        "bad-request",
        "/bin/cat \"$W/fixture.jsonl\"",
        r#"{"request_id":5}"#,
    ),
];

fn long(len: usize) -> Vec<u8> {
    let mut line = b"{\"MESSAGE\":\"".to_vec();
    line.resize(len - 2, b'a');
    line.extend_from_slice(b"\"}\n");
    line
}

fn bin_with(body: &str) -> FakeBin {
    let bin = FakeBin::new();
    bin.file("fixture.jsonl", FIXTURE)
        .file("long-ok.jsonl", &long(262_143))
        .file("long-bad.jsonl", &long(262_144))
        .program("journalctl", &format!("W=\"$D\"\n{body}"));
    bin
}

fn go(name: &str) -> Value {
    let path = format!(
        "{}/src/tests/testdata/go/journal-query-{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Messages of lines whose time Go took from its clock.
fn now_used() -> Vec<String> {
    let go: Value = serde_json::from_str(GO_LINES).unwrap();
    go["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["now_used"] == true)
        .map(|row| row["entry"]["message"].as_str().unwrap().to_owned())
        .collect()
}

/// A message over 1 KiB that repeats one character, as `"<count> × <c>"`:
/// the form Go's answer for the 256 KiB−1 line is kept in.
fn compact(reply: &mut Value) {
    for entry in reply["data"]["entries"]
        .as_array_mut()
        .into_iter()
        .flatten()
    {
        let Some(message) = entry["message"].as_str() else {
            continue;
        };
        let mut chars = message.chars();
        if let Some(first) = chars.next()
            && message.len() > 1024
            && chars.all(|c| c == first)
        {
            entry["message"] = json!(format!("{} × {first}", message.chars().count()));
        }
    }
}

/// Go's message and Rust's, alike but for two documented differences:
/// Go's `null` for no entries is `[]` here, and times taken from the clock
/// (lines without `__REALTIME_TIMESTAMP`) differ.
fn assert_same(name: &str, go: &Value, rust: &Value) {
    let mut go = go.clone();
    if go["data"]["entries"].is_null() && !go.is_null() {
        go["data"]["entries"] = json!([]);
    }
    let mut rust = rust.clone();
    compact(&mut rust);
    let skip = now_used();
    for (g, r) in go["data"]["entries"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .zip(rust["data"]["entries"].as_array_mut().into_iter().flatten())
    {
        // The long lines carry no time either.
        let long = g["message"].as_str().is_some_and(|m| m.ends_with(" × a"));
        if long || skip.iter().any(|m| g["message"] == m.as_str()) {
            g["timestamp"] = Value::Null;
            r["timestamp"] = Value::Null;
        }
    }
    assert_eq!(go, rust, "{name}");
}

fn handle(commands: Commands, request: &str) -> Value {
    let mut features = Features::new();
    crate::logs::register(&mut features, &super::settings(), &commands);
    let message = Message {
        r#type: MSG_JOURNAL_QUERY.into(),
        id: "envelope".into(),
        data: Some(serde_json::value::RawValue::from_string(request.to_owned()).unwrap()),
    };
    let reply = features.handler(MSG_JOURNAL_QUERY).unwrap()(&message);
    reply.map_or(Value::Null, |reply| serde_json::to_value(&reply).unwrap())
}

// Faults: a reply field differs from Go's (entries, order, request ID as
// the message ID, error text for a too-long line, a failed run with or
// without output, a signal); a request that does not decode gets a reply
// (Go sends none); the line limit is not Go's 256 KiB.
#[test]
fn query_replies_match_go() {
    let _serial = serial();
    for (name, body, request) in CASES {
        let bin = bin_with(body);
        let rust = handle(Commands::new(bin.policy(&[])), request);
        let go = go(name);
        let go = go
            .as_array()
            .and_then(|sent| sent.first())
            .cloned()
            .unwrap_or(Value::Null);
        assert_same(name, &go, &rust);
    }
}

// Faults: the query runs although the rules block journalctl, or runs a
// journalctl outside the agent's PATH, or the texts differ from Go's; the
// timeout is not applied, or a timed-out run is reported as a failure.
#[test]
fn refused_missing_and_slow_journalctl_match_go() {
    let _serial = serial();
    let bin = bin_with("/bin/cat \"$W/fixture.jsonl\"");
    let rust = handle(
        Commands::new(bin.policy(&["journalctl"])),
        r#"{"request_id":"q3","limit":7}"#,
    );
    assert_same("blocked", &go("blocked")[0], &rust);
    assert!(
        bin.calls("journalctl").is_none(),
        "a blocked journalctl ran"
    );

    let empty = FakeBin::new();
    let rust = handle(
        Commands::new(empty.policy(&[])),
        r#"{"request_id":"q3","limit":7}"#,
    );
    assert_same("missing", &go("missing")[0], &rust);

    let bin = bin_with("exec /bin/sleep 5");
    let request = JournalQueryData {
        request_id: "q3".into(),
        limit: 7,
        ..JournalQueryData::default()
    };
    let started = std::time::Instant::now();
    let reply = answer(&bin.policy(&[]), request, Duration::from_millis(500));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let rust = serde_json::to_value(Message::with_data(MSG_JOURNAL_ENTRIES, "q3", &reply).unwrap())
        .unwrap();
    assert_same("timeout", &go("timeout")[0], &rust);
}

/// Go's arguments with each short option and its value written as the
/// full name joined with `=`.
fn full_names(go: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut args = go.iter();
    while let Some(arg) = args.next() {
        let long = match arg.as_str() {
            "-n" => "--lines",
            "-u" => "--unit",
            "-p" => "--priority",
            "-r" => {
                out.push("--reverse".to_owned());
                continue;
            }
            "--since" | "--until" | "--grep" => arg.as_str(),
            _ => {
                out.push(arg.clone());
                continue;
            }
        };
        out.push(format!("{long}={}", args.next().unwrap()));
    }
    out
}

// Faults: an option is dropped, gets another value than Go's (trimmed
// differently, limit not clamped to 1..1000 as Go's), or is passed so a
// value can be read as an option (`--unit --rotate`), or `--lines` is
// given its value as a separate word (journalctl then ignores it).
#[test]
fn arguments_are_go_values_with_full_names() {
    let _serial = serial();
    let bin = bin_with(REC);
    let request = CASES[1].2;
    handle(Commands::new(bin.policy(&[])), request);
    let rust: Vec<String> = std::fs::read_to_string(bin.dir.join("args"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let go: Vec<String> = std::fs::read_to_string(format!(
        "{}/src/tests/testdata/go/journal-query-options.args",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .lines()
    .map(str::to_owned)
    .collect();
    assert_eq!(rust, full_names(&go));
    assert!(
        rust.contains(&"--unit=--rotate".to_owned()) && rust.contains(&"--lines=1000".to_owned())
    );
    for limit in [-5, 0, 7, 1000, 1001] {
        let path = format!(
            "{}/src/tests/testdata/go/journal-args-limit{limit}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let go: Vec<String> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let request = JournalQueryData {
            request_id: "a".into(),
            limit,
            ..JournalQueryData::default()
        };
        assert_eq!(query_args(&request), full_names(&go), "limit {limit}");
    }
}
