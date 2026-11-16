//! The status body against the protocol's local agent contract, offline:
//! the copy of the contract is the one SOURCE.json names, the checks here
//! accept every fixture, and each fixture's values written by this crate
//! give Go's bytes exactly (so the ETag matches Go's for the same state).

mod support;

use labtether_agent_local_api::body;
use labtether_agent_local_api::gojson;
use labtether_agent_local_api::gotime::{GoTime, parse_rfc3339};
use serde_json::Value;
use sha2::{Digest, Sha256};
use support::{FIXTURES, code_problems, codes, compact, contract_dir, fixture, view_from_fixture};

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// Fault: the copied contract drifts from the protocol commit it names (a
// fixture edited by hand to make a test pass, a file added or lost).
#[test]
fn copy_matches_source() {
    let dir = contract_dir();
    let source: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("SOURCE.json")).unwrap()).unwrap();
    assert_eq!(source["commit"].as_str().map(str::len), Some(40));
    let files = source["files"].as_array().unwrap();
    let mut listed: Vec<String> = Vec::new();
    for entry in files {
        let name = entry["name"].as_str().unwrap();
        let data = std::fs::read(dir.join(name)).unwrap();
        assert_eq!(
            hex(&data),
            entry["sha256"].as_str().unwrap(),
            "{name} changed"
        );
        listed.push(name.to_owned());
    }
    let mut present = vec!["codes.v1.json".to_owned()];
    for entry in std::fs::read_dir(dir.join("fixtures/status")).unwrap() {
        present.push(format!(
            "fixtures/status/{}",
            entry.unwrap().file_name().to_string_lossy()
        ));
    }
    listed.sort();
    present.sort();
    assert_eq!(listed, present, "files differ from SOURCE.json");
    let named: Vec<String> = FIXTURES
        .iter()
        .map(|n| format!("fixtures/status/{n}.json"))
        .collect();
    assert!(named.iter().all(|n| present.contains(n)) && named.len() + 1 == present.len());
}

// Fault: the code-rule checker used by the live tests is wrong: it refuses
// a real Go body, or accepts a broken one.
#[test]
fn checker_accepts_fixtures_and_refuses_broken_bodies() {
    let codes = codes();
    for name in FIXTURES {
        let (_, value) = fixture(name);
        assert_eq!(
            code_problems(&value, &codes),
            Vec::<String>::new(),
            "{name}"
        );
    }
    let (_, connected) = fixture("connected");
    // Each broken body breaks one rule only, and the problem must name it.
    let broken: [(&[(&str, Value)], &str); 6] = [
        (
            &[("connection_state", Value::from("online"))],
            "is not in the set",
        ),
        (
            &[
                ("connection_state", Value::from("disconnected")),
                ("connected", Value::from(false)),
                ("last_error", Value::from("transient")),
            ],
            "does not go with \"disconnected\"",
        ),
        (&[("connected", Value::from(false))], "connected false"),
        (
            &[("enrollment_error", Value::from("words"))],
            "enrollment_error while connected",
        ),
        (
            &[("uptime", Value::from("2h14m33.5s"))],
            "is not Go duration text",
        ),
        (
            &[("started_at", Value::from("2026-11-14T07:26:34.418236510Z"))],
            "is not Go time text",
        ),
    ];
    for (changes, expected) in broken {
        let mut body = connected.clone();
        for (key, value) in changes {
            body[*key] = value.clone();
        }
        let problems = code_problems(&body, &codes);
        assert!(
            problems.iter().any(|p| p.contains(expected)),
            "{changes:?}: want {expected:?}, got {problems:?}"
        );
    }
}

// Faults: a field out of Go's order, an optional field sent empty instead
// of left out, a float written as 4.8213377024e10 or 48213377024.0, a time
// with trailing zeros or another zone, the uptime bucketing or the zero
// start time handled unlike Go. Any of these changes the bytes, so the
// ETag would differ from Go's and the body from the contract.
#[test]
fn every_fixture_is_written_byte_for_byte() {
    for name in FIXTURES {
        let (text, value) = fixture(name);
        let (view, local) = view_from_fixture(&value);
        let status = body::status(&view, &local).unwrap();
        assert_eq!(status.body, format!("{}\n", compact(&text)), "{name}");
        assert!(
            status.etag.starts_with('"') && status.etag.len() == 66,
            "{name}"
        );
    }
}

// Fault: the ETag changes every second (the apps never get 304) or stays
// the same across a minute (a stale page).
#[test]
fn etag_buckets_uptime_by_minute() {
    let (_, value) = fixture("connected");
    let (mut view, local) = view_from_fixture(&value);
    let tag = |view: &_| body::status(view, &local).unwrap().etag;
    view.uptime = std::time::Duration::from_secs(8040);
    let first = tag(&view);
    view.uptime = std::time::Duration::from_secs(8099);
    assert_eq!(tag(&view), first, "same minute, same tag");
    view.uptime = std::time::Duration::from_secs(8100);
    assert_ne!(tag(&view), first, "next minute, new tag");
}

// Faults: `*`, a weak tag or one entry of a list does not match, so the
// app downloads the page every poll; or any tag matches.
#[test]
fn if_none_match_follows_go() {
    let tag = "\"abc123\"";
    for (header, matches) in [
        ("\"abc123\"", true),
        ("W/\"abc123\"", true),
        ("w/\"abc123\"", true),
        ("abc123", true),
        ("*", true),
        ("\"x\", \"abc123\"", true),
        ("\"abc124\"", false),
        ("", false),
        ("W/", false),
    ] {
        assert_eq!(body::etag_matches(header, tag), matches, "{header:?}");
    }
}

// Faults: a value Go cannot encode is sent as null or text instead of
// Go's 500; Go's HTML escapes and float forms differ.
#[test]
fn json_values_follow_go() {
    let (_, value) = fixture("connected");
    let (mut view, local) = view_from_fixture(&value);
    view.latest.sample.cpu_percent = f64::NAN;
    assert_eq!(body::status(&view, &local), Err(body::BodyError::NonFinite));
    let mut out = String::new();
    gojson::string(&mut out, "a<b>&\u{2028}\"\\\n\u{1}\u{8}\u{7f}\u{e9}");
    let bs = '\\';
    let want = format!(
        "\"a{bs}u003cb{bs}u003e{bs}u0026{bs}u2028{bs}\"{bs}{bs}{bs}n{bs}u0001{bs}b\u{7f}\u{e9}\""
    );
    assert_eq!(out, want);
    for (number, text) in [
        (0.0, "0"),
        (12.5, "12.5"),
        (48213377024.0, "48213377024"),
        (1e21, "1e+21"),
        (1.5e-7, "1.5e-7"),
        (0.000001, "0.000001"),
        (-0.0, "-0"),
    ] {
        let mut out = String::new();
        gojson::number(&mut out, number).unwrap();
        assert_eq!(out, text);
    }
}

// Fault: a Hub alert time is shown in another zone, loses its fraction, or
// a time Go cannot read is not shown as Go's zero time.
#[test]
fn alert_times_read_like_go() {
    for (raw, shown) in [
        ("2026-11-14T09:12:40Z", "2026-11-14T09:12:40Z"),
        ("2026-11-14T08:55:03.512000Z", "2026-11-14T08:55:03.512Z"),
        ("2026-11-14T19:12:40+10:00", "2026-11-14T19:12:40+10:00"),
        ("2026-11-14T09:12:40+00:00", "2026-11-14T09:12:40Z"),
        (
            "2026-11-14T09:12:40.1234567891Z",
            "2026-11-14T09:12:40.123456789Z",
        ),
    ] {
        assert_eq!(
            parse_rfc3339(raw).unwrap().rfc3339_nano().as_deref(),
            Some(shown),
            "{raw}"
        );
    }
    for bad in [
        "",
        "yesterday",
        "2026-02-30T00:00:00Z",
        "2026-11-14 09:12:40Z",
        "2026-11-14T24:00:00Z",
    ] {
        assert_eq!(parse_rfc3339(bad), None, "{bad}");
    }
    assert_eq!(
        GoTime::ZERO.rfc3339_nano().as_deref(),
        Some("0001-01-01T00:00:00Z")
    );
}
