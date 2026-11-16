//! Output parsers against captured text. `testdata/debian13-*.txt` is what
//! `systemctl`, `dpkg-query` and `apt-get` printed on a Debian 13 lab VM
//! (systemd 257) with the Go agent's arguments; two unit names that held a
//! person's account and a lab machine's name were replaced with neutral
//! ones. Output of the other package managers is written in each tool's
//! documented form (no such host was available).

use std::collections::{HashMap, HashSet};

use super::gotext::{ERR_TOO_LONG, MAX_SCAN_LINE, fields, go_quote, lossy, scan_lines, trim_space};
use super::services::{ServiceRow, parse_unit_files, parse_units, unloaded_units};

mod journal;
mod packages;
mod upgradable;

const UNITS: &[u8] = include_bytes!("testdata/debian13-units.txt");
const UNIT_FILES: &[u8] = include_bytes!("testdata/debian13-unit-files.txt");

fn find<'a>(rows: &'a [ServiceRow], name: &str) -> &'a ServiceRow {
    rows.iter()
        .find(|row| row.name == name)
        .unwrap_or_else(|| panic!("{name} missing"))
}

// Faults: the name keeps `.service`; the description is cut to its first
// word; the unit file state comes from the wrong column or the wrong key;
// a not-found unit is dropped; systemctl's order is not kept.
#[test]
fn units_follow_systemctl_order_and_go_fields() {
    let enabled = parse_unit_files(UNIT_FILES);
    let rows = parse_units(UNITS, &enabled);
    assert_eq!(rows.len(), 149 + 19, "149 listed units plus 19 unloaded");
    assert_eq!(rows[0].name, "accounts-daemon");
    assert_eq!(
        find(&rows, "actions.runner.example-org-app.runner01"),
        &ServiceRow {
            name: "actions.runner.example-org-app.runner01".into(),
            description: "GitHub Actions Runner (example-org-app.runner01)".into(),
            active_state: "failed".into(),
            sub_state: "failed".into(),
            enabled: "enabled".into(),
            load_state: "loaded".into(),
        }
    );
    let auditd = find(&rows, "auditd");
    assert_eq!(
        (auditd.load_state.as_str(), auditd.enabled.as_str()),
        ("not-found", "")
    );
    assert_eq!(auditd.description, "auditd.service");
    let fsck = find(&rows, r"systemd-fsck@dev-disk-by\x2duuid-E3BA\x2d5E9B");
    assert_eq!(
        fsck.description,
        "File System Check on /dev/disk/by-uuid/E3BA-5E9B"
    );
    assert_eq!(find(&rows, "apparmor").sub_state, "exited");
}

// Fault: installed services list-units leaves out (disabled, never run)
// are missing, are unsorted, or static, masked, alias and template units
// are added (nothing can start them by name).
#[test]
fn unloaded_units_are_added_sorted_and_filtered() {
    let enabled = parse_unit_files(UNIT_FILES);
    let rows = parse_units(UNITS, &enabled);
    let added: Vec<&str> = rows[149..].iter().map(|r| r.name.as_str()).collect();
    assert_eq!(added.len(), 19);
    assert_eq!(
        added[..3],
        ["NetworkManager-dispatcher", "console-getty", "debug-shell"]
    );
    assert_eq!(added[18], "systemd-time-wait-sync");
    assert!(rows[149..].iter().all(|r| r.active_state == "inactive"
        && r.sub_state == "dead"
        && r.load_state.is_empty()
        && r.description.is_empty()));
    let states = HashMap::from(
        [
            ("a.service", "static"),
            ("b.service", "masked"),
            ("c.service", "alias"),
            ("d@.service", "enabled"),
            ("e.socket", "enabled"),
            ("f.service", "linked-runtime"),
            ("g.service", "indirect"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned())),
    );
    let names: Vec<String> = unloaded_units(&states, &HashSet::new())
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["f", "g"]);
}

// Faults: a description's inner white space is kept as printed (Go joins
// the words with one space); a line with fewer than four words is listed;
// a Unicode space is not a separator; a later list-unit-files line for the
// same unit does not win; invalid UTF-8 is joined into one U+FFFD.
#[test]
fn odd_lines_are_read_as_go_reads_them() {
    let units: &[u8] = b"  one.service loaded active running Two  spaced\tdescription \r\n\
        short.service loaded active\n\n\
        nb.service\xc2\xa0loaded active exited x\xe2\x80\x83y\n\
        bad.service loaded active running caf\xc3\xff\n";
    let files = b"one.service disabled enabled\none.service enabled enabled\nlonely\n";
    let enabled = parse_unit_files(files);
    assert_eq!(
        enabled.get("one.service").map(String::as_str),
        Some("enabled")
    );
    assert!(!enabled.contains_key("lonely"));
    let rows = parse_units(units, &enabled);
    let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["one", "nb", "bad"]);
    assert_eq!(rows[0].description, "Two spaced description");
    assert_eq!(rows[0].enabled, "enabled");
    assert_eq!(rows[1].description, "x y");
    assert_eq!(rows[2].description, "caf\u{fffd}\u{fffd}");
}

// Faults: a CRLF line keeps its `\r`; a line at the Go scanner's limit is
// read, or a line just under it is refused; the last line without `\n` is
// lost.
#[test]
fn scan_lines_follow_bufio_scanner() {
    let (lines, end) = scan_lines(b"a\r\n\nb");
    assert_eq!(lines, [&b"a"[..], b"", b"b"]);
    assert_eq!(end, Ok(()));
    let mut text = vec![b'x'; MAX_SCAN_LINE - 1];
    text.extend_from_slice(b"\nnext\n");
    assert_eq!(scan_lines(&text).0.len(), 2);
    let mut text = b"first\n".to_vec();
    text.extend(vec![b'x'; MAX_SCAN_LINE]);
    text.extend_from_slice(b"\nafter\n");
    let (lines, end) = scan_lines(&text);
    assert_eq!((lines, end), (vec![&b"first"[..]], Err(ERR_TOO_LONG)));
}

// Faults: an invalid byte counts as a space or is dropped; `%q` text
// differs from Go's for quotes, control bytes and invalid bytes.
#[test]
fn go_text_helpers_match_go() {
    assert_eq!(trim_space(b"\xff \t"), b"\xff");
    assert_eq!(trim_space("\u{3000}x\u{85}".as_bytes()), b"x");
    assert_eq!(fields(b"a\xffb c"), [&b"a\xffb"[..], b"c"]);
    assert_eq!(lossy(b"a\xe2\x82b"), "a\u{fffd}\u{fffd}b");
    assert_eq!(
        go_quote(b"a\"b\\\n\x01\xff\xc3\xa9"),
        r#""a\"b\\\n\x01\xffé""#
    );
}
