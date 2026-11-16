//! The Users and Scheduled jobs readers against the Go agent's own answers.
//!
//! `testdata/` holds `who`, `systemctl list-timers` and crontab text
//! captured on the lab VM (user names, addresses and unit names replaced
//! with neutral ones), edge cases written by hand, and two zone files from
//! the VM. `testdata/go/` holds what the Go agent's code made of each
//! fixture (`ParseUserSessionsOutput`, `CollectSystemdTimers` with a
//! stand-in `systemctl` that prints the fixture, `CollectCrontabsFromPaths`),
//! recorded on the lab VM by a small program built from the agent's Go
//! source (see the step's evidence). Every test compares field by field.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::linux::cron::Entry;
use crate::linux::cron::crontab::{CrontabPaths, collect_crontabs};
use crate::linux::cron::timers::parse_list_timers;
use crate::linux::gotime::{Zone, from_tzif};
use crate::linux::who::parse_who;

const ZONES: [&str; 3] = ["Australia_Sydney", "America_New_York", "UTC"];

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(relative)
}

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(testdata(relative)).unwrap()
}

pub(super) fn zone(name: &str) -> Zone {
    if name == "UTC" {
        return Zone::utc();
    }
    from_tzif(&read(&format!("zoneinfo/{name}"))).unwrap()
}

fn oracle(name: &str) -> Value {
    serde_json::from_slice(&read(&format!("go/{name}"))).unwrap()
}

/// A JSON list (Go sends `null` for an empty one) as rows of the named
/// string fields, an absent field being empty (Go's `omitempty`).
fn rows(list: &Value, keys: &[&str]) -> Vec<Vec<String>> {
    let empty = Vec::new();
    list.as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|item| {
            keys.iter()
                .map(|key| item[*key].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .collect()
}

const ENTRY_KEYS: [&str; 5] = ["source", "schedule", "command", "user", "next_run"];

fn entry_rows(entries: &[Entry]) -> Vec<Vec<String>> {
    entries
        .iter()
        .map(|e| {
            vec![
                e.source.to_owned(),
                e.schedule.clone(),
                e.command.clone(),
                e.user.clone(),
                e.next_run.clone(),
            ]
        })
        .collect()
}

// Faults: login times read as UTC instead of the host's zone (hours off on
// any host not set to UTC), a yearless C-locale time dated wrongly (the
// year, last year for a future date, Feb 29 in a common year), Go's choice
// in a summer-time gap or overlap not followed, a tmux pane shown as a
// remote host, the comment kept in the login time, a short line not
// skipped, odd white space or a carriage return mis-split, bytes that are
// not UTF-8 replaced differently from Go's JSON, or no users giving
// anything but an empty list.
#[test]
fn who_output_matches_go_in_every_zone() {
    for zone_name in ZONES {
        let local = zone(zone_name);
        for fixture in ["who-c", "who-utf8", "who-edge", "who-empty"] {
            let go = oracle(&format!("{fixture}.{zone_name}.json"));
            let now = go["now"].as_i64().unwrap();
            let sessions = parse_who(&read(&format!("{fixture}.txt")), &local, now);
            let got: Vec<Vec<String>> = sessions
                .into_iter()
                .map(|s| vec![s.username, s.terminal, s.remote_host, s.login_time])
                .collect();
            let want = rows(
                &go["result"],
                &["username", "terminal", "remote_host", "login_time"],
            );
            assert_eq!(got, want, "{fixture} in {zone_name}");
        }
    }
}

// Faults: rows before the header or after the summary listed, a short row
// kept, the unit and the unit it starts swapped, a next run in `n/a` or `-`
// parsed, a zone abbreviation not looked up in the host's zone (or a known
// one moved, an unknown one given an offset Go does not give), summer time
// after 2037 (the zone file's closing rule) wrong, a lower-case weekday or
// a fraction of a second refused, or an impossible date accepted.
#[test]
fn timer_rows_match_go_in_every_zone() {
    for zone_name in ZONES {
        let local = zone(zone_name);
        for fixture in ["timers-vm", "timers-edge", "timers-none"] {
            let go = oracle(&format!("{fixture}.{zone_name}.json"));
            let got = entry_rows(&parse_list_timers(&read(&format!("{fixture}.txt")), &local));
            assert_eq!(
                got,
                rows(&go["result"], &ENTRY_KEYS),
                "{fixture} in {zone_name}"
            );
        }
    }
}

fn paths(cron_d: &str, system: &str, user_dirs: &[&str]) -> CrontabPaths {
    CrontabPaths {
        user_dirs: user_dirs.iter().map(PathBuf::from).collect(),
        cron_d: PathBuf::from(cron_d),
        system: PathBuf::from(system),
    }
}

// Faults: comments, environment lines, short lines or folders listed; a
// command starting with a digit or `*` that holds `=` dropped; `@reboot`
// or system-file users read from the wrong word; odd spacing kept in the
// command; dot files or name order not Go's; an empty crontab giving rows;
// a missing source reported while another was read; a file given as a
// folder worded other than Go's `open ...: not a directory`; or Go's
// error wording changed (the Hub shows it).
#[test]
fn crontabs_match_go() {
    let runs = [
        (
            "crontabs-fixture.json",
            paths(
                "testdata/cron/cron.d",
                "testdata/cron/crontab",
                &["testdata/cron/crontabs", "testdata/cron/missing"],
            ),
        ),
        (
            "crontabs-none.json",
            paths(
                "testdata/cron/missing.d",
                "testdata/cron/missing-crontab",
                &["testdata/cron/missing"],
            ),
        ),
        (
            "crontabs-notdir.json",
            paths(
                "testdata/cron/cron.d",
                "testdata/cron/missing-crontab",
                &["testdata/cron/crontab"],
            ),
        ),
    ];
    // Go ran in the platform crate's folder, where cargo runs its tests, so
    // the relative paths in the error text are the same.
    for (name, paths) in runs {
        let go = oracle(name);
        let (entries, error) = collect_crontabs(&paths);
        assert_eq!(
            entry_rows(&entries),
            rows(&go["result"], &ENTRY_KEYS),
            "{name}"
        );
        assert_eq!(error.as_deref(), go["error"].as_str(), "{name}");
    }
}
