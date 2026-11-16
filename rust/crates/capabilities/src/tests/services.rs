//! The service list with fake `systemctl` programs, run through the real
//! command rules: arguments, environment, refusal, and Go's fallbacks.

use std::time::Duration;

use labtether_protocol::ServiceListData;
use serde_json::json;

use super::fakebin::{FakeBin, serial};
use crate::services::{GO_TIMEOUTS, Timeouts, answer, list_services};

const UNITS: &str = "ssh.service loaded active running OpenBSD Secure Shell server\n\
    cups.service not-found inactive dead cups.service\n";
const UNIT_FILES: &str = "ssh.service enabled enabled\nrsync.service disabled enabled\n";

fn systemctl(bin: &FakeBin, files_exit: i32, units_body: &str) {
    bin.file("units.out", UNITS.as_bytes())
        .file("unit-files.out", UNIT_FILES.as_bytes())
        .program(
            "systemctl",
            &format!(
                "case \"$1\" in\n list-unit-files) /bin/cat \"$D/unit-files.out\"; exit {files_exit};;\n list-units) {units_body};;\nesac"
            ),
        );
}

fn names_and_enabled(bin: &FakeBin, timeouts: Timeouts) -> Vec<(String, String)> {
    list_services(&bin.policy(&[]), timeouts)
        .unwrap()
        .into_iter()
        .map(|r| (r.name, r.enabled))
        .collect()
}

// Faults: systemctl is run with other arguments or in another order than
// Go's; the child gets the agent's whole environment (a variable outside
// Go's list reaches it) instead of the sanitized one; the unloaded
// service from list-unit-files is missing from the reply.
#[test]
fn service_list_runs_go_commands_with_the_clean_environment() {
    let _serial = serial();
    let bin = FakeBin::new();
    systemctl(&bin, 0, "/bin/cat \"$D/units.out\"");
    let rows = list_services(&bin.policy(&[]), GO_TIMEOUTS).unwrap();
    let reply = answer(
        ServiceListData {
            request_id: "s1".into(),
        },
        Ok(rows),
    );
    assert_eq!(
        serde_json::to_value(&reply).unwrap(),
        json!({"request_id": "s1", "services": [
            {"name": "ssh", "description": "OpenBSD Secure Shell server", "active_state": "active",
             "sub_state": "running", "enabled": "enabled", "load_state": "loaded"},
            {"name": "cups", "description": "cups.service", "active_state": "inactive",
             "sub_state": "dead", "enabled": "", "load_state": "not-found"},
            {"name": "rsync", "description": "", "active_state": "inactive",
             "sub_state": "dead", "enabled": "disabled", "load_state": ""}]})
    );
    assert_eq!(
        bin.calls("systemctl").unwrap(),
        [
            "list-unit-files --type=service --no-pager --plain --no-legend",
            "list-units --type=service --all --no-pager --plain --no-legend",
        ]
    );
    assert_eq!(
        bin.env("systemctl"),
        [
            "HOME=/home/demo".to_owned(),
            "LANG=de_DE.UTF-8".to_owned(),
            "LC_ALL=de_DE.UTF-8".to_owned(),
            format!("PATH={}", bin.dir.display()),
        ]
    );
}

// Faults: the page starts systemctl without asking the command rules, or
// asks and starts it anyway; the refusal is not the reply's error.
#[test]
fn blocked_systemctl_is_refused_and_never_started() {
    let _serial = serial();
    let bin = FakeBin::new();
    systemctl(&bin, 0, "/bin/cat \"$D/units.out\"");
    let policy = bin.policy(&["systemctl"]);
    let refusal = policy.validate_exec_binary("systemctl").unwrap_err();
    assert_eq!(
        list_services(&policy, GO_TIMEOUTS),
        Err(format!("systemctl list-units: {refusal}"))
    );
    assert_eq!(bin.calls("systemctl"), None, "systemctl was started");
}

// Faults: a failed list-unit-files fails the page (Go lists units without
// unit file states); a failed, missing, silent or hung list-units does not
// give Go's error text.
#[test]
fn service_list_fallbacks_follow_go() {
    let _serial = serial();
    let bin = FakeBin::new();
    systemctl(&bin, 1, "/bin/cat \"$D/units.out\"");
    assert_eq!(
        names_and_enabled(&bin, GO_TIMEOUTS),
        [
            ("ssh".to_owned(), String::new()),
            ("cups".to_owned(), String::new())
        ]
    );

    let bin = FakeBin::new();
    systemctl(&bin, 0, "echo 'Failed to connect to bus'; exit 3");
    assert_eq!(
        list_services(&bin.policy(&[]), GO_TIMEOUTS),
        Err("systemctl list-units: exit status 3".into())
    );

    let bin = FakeBin::new();
    // Empty list-units output: no error, and every startable unit file
    // comes back as unloaded (Go does the same).
    systemctl(&bin, 0, "exit 0");
    assert_eq!(
        names_and_enabled(&bin, GO_TIMEOUTS),
        [
            ("rsync".to_owned(), "disabled".to_owned()),
            ("ssh".to_owned(), "enabled".to_owned())
        ]
    );

    let bin = FakeBin::new();
    systemctl(&bin, 0, "exec /bin/sleep 5");
    let short = Timeouts {
        unit_files: GO_TIMEOUTS.unit_files,
        units: Duration::from_millis(300),
    };
    assert_eq!(
        list_services(&bin.policy(&[]), short),
        Err("systemctl list-units timed out".into())
    );

    let empty = FakeBin::new();
    assert_eq!(
        list_services(&empty.policy(&[]), GO_TIMEOUTS),
        Err("systemctl list-units: exec: \"systemctl\": executable file not found in $PATH".into())
    );
}
