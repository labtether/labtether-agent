//! The Users and Scheduled jobs pages start `who` and `systemctl`. These
//! tests run the real handlers with stand-in programs on `PATH` (shell
//! scripts that record how they were started) to show that every start
//! goes through the command rules: a blocked program is refused and never
//! starts, the child gets the cleaned environment and Go's arguments, and
//! each way a command can end gives Go's reply.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use labtether_agent_capabilities::{Commands, all};
use labtether_agent_config::{Environment, HostFacts, load};
use labtether_agent_security::CommandPolicy;
use labtether_protocol::{CronListedData, Message, UsersListedData};
use serde_json::json;

struct Bin(PathBuf);

impl Bin {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lt-command-pages-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// A stand-in program: records its environment and arguments, prints
    /// `output`, then runs `tail` (an exit or a signal).
    fn program(&self, name: &str, output: &str, tail: &str) {
        let dir = self.0.display();
        let script = format!(
            "#!/bin/sh\n/usr/bin/env > {dir}/{name}.env\nprintf '%s\\n' \"$@\" > {dir}/{name}.args\n/bin/cat <<'OUT'\n{output}OUT\n{tail}\n"
        );
        let path = self.0.join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn started(&self, name: &str) -> bool {
        self.0.join(format!("{name}.env")).exists()
    }

    fn read(&self, file: &str) -> String {
        fs::read_to_string(self.0.join(file)).unwrap()
    }
}

impl Drop for Bin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The handler's reply to `request`, with the agent's environment `extra`
/// and `PATH` set to the stand-in folder only.
fn ask(bin: &Path, request: &str, extra: &[(&str, &str)]) -> serde_json::Value {
    let state = bin.join("state");
    let path = |name: &str| state.join(name).display().to_string();
    let mut pairs = vec![
        ("LABTETHER_TOKEN_FILE".to_owned(), path("agent-token")),
        (
            "LABTETHER_AGENT_SETTINGS_FILE".to_owned(),
            path("agent-config.json"),
        ),
        ("PATH".to_owned(), bin.display().to_string()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
        ("LTQA_SECRET".to_owned(), "do-not-pass".to_owned()),
    ];
    pairs.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let env = Environment::from_pairs(pairs);
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    let settings = load(&env, &host).unwrap().settings;
    let policy = CommandPolicy::new(&settings.command_security, &env);
    let features = all(&settings, &Commands::new(policy));
    let message: Message =
        serde_json::from_value(json!({"type": request, "id": "e", "data": {"request_id": "r1"}}))
            .unwrap();
    let reply = features.handler(request).unwrap()(&message).unwrap();
    reply.decode().unwrap()
}

fn users(bin: &Bin, extra: &[(&str, &str)]) -> UsersListedData {
    serde_json::from_value(ask(&bin.0, "users.list", extra)).unwrap()
}

fn cron(bin: &Bin, extra: &[(&str, &str)]) -> CronListedData {
    serde_json::from_value(ask(&bin.0, "cron.list", extra)).unwrap()
}

const WHO: &str = "demo     pts/0        2026-11-16 12:15 (192.0.2.10)\n";

// Faults: `who` started without the command rules (the agent's whole
// environment, with its secrets, reaches the child), with arguments Go
// does not pass, or its output not parsed into sessions.
#[test]
fn who_runs_through_the_rules_with_the_cleaned_environment() {
    let bin = Bin::new();
    bin.program("who", WHO, "exit 0");
    let reply = users(&bin, &[]);
    assert_eq!(reply.error, "");
    let session = &reply.sessions[0];
    assert_eq!(
        (session.username.as_str(), session.terminal.as_str()),
        ("demo", "pts/0")
    );
    assert_eq!(session.remote_host, "192.0.2.10");
    assert_eq!(session.login_time, "2026-11-16T12:15:00Z");
    assert_eq!(bin.read("who.args"), "\n", "who takes no arguments");
    let env = bin.read("who.env");
    assert!(env.lines().any(|l| l == "LANG=C.UTF-8"), "{env}");
    assert!(env.lines().any(|l| l == "TZ=UTC"), "{env}");
    for line in env.lines() {
        assert!(!line.starts_with("LTQA_SECRET"), "secret passed: {env}");
        assert!(
            !line.starts_with("LABTETHER_"),
            "agent setting passed: {env}"
        );
    }
}

// Fault: a program on the blocked list is started anyway, or the refusal
// is not sent to the Hub.
#[test]
fn a_blocked_who_is_refused_and_never_starts() {
    let bin = Bin::new();
    bin.program("who", WHO, "exit 0");
    let reply = users(&bin, &[("LABTETHER_EXEC_BLOCKED_BINARIES", "who")]);
    assert_eq!(reply.error, r#"command "who" blocked by runtime policy"#);
    assert!(reply.sessions.is_empty());
    assert!(!bin.started("who"), "the blocked who was started");
}

// Faults: a missing `who`, a non-zero exit, a signal or too much output
// gives a reply without Go's error text (the Hub shows it, and matches the
// missing-program text), or keeps sessions from a failed run.
#[test]
fn each_way_who_can_fail_gives_go_text() {
    let bin = Bin::new();
    let missing = users(&bin, &[]);
    assert_eq!(
        missing.error,
        r#"exec: "who": executable file not found in $PATH"#
    );
    for (tail, want) in [
        ("exit 3", "exit status 3"),
        ("kill -9 $$", "signal: killed"),
        (
            "exec /usr/bin/head -c 8388700 /dev/zero",
            "command output exceeded capture limit (8388608 bytes)",
        ),
    ] {
        bin.program("who", WHO, tail);
        let reply = users(&bin, &[]);
        assert_eq!(reply.error, want, "{tail}");
        assert!(reply.sessions.is_empty(), "{tail}");
    }
}

const TIMERS: &str = "NEXT                        LEFT LAST                        PASSED UNIT         ACTIVATES\n\
Mon 2026-11-16 12:33:43 UTC 18min Mon 2026-11-16 11:31:18 UTC 43min ago anacron.timer anacron.service\n\
-                              - Mon 2026-11-16 12:15:00 UTC 1s ago scratch.timer scratch.service\n\
\n2 timers listed.\n";

// Faults: `systemctl` started without the rules or with arguments other
// than Go's, or its rows not listed first with Go's fields.
#[test]
fn systemctl_runs_through_the_rules_with_go_arguments() {
    let bin = Bin::new();
    bin.program("systemctl", TIMERS, "exit 0");
    let reply = cron(&bin, &[]);
    assert_eq!(
        bin.read("systemctl.args"),
        "list-timers\n--all\n--no-pager\n--plain\n"
    );
    assert!(!bin.read("systemctl.env").contains("LTQA_SECRET"));
    assert!(!reply.error.contains("systemd timers"), "{}", reply.error);
    let first: Vec<(&str, &str, &str, &str)> = reply.entries[..2]
        .iter()
        .map(|e| {
            (
                e.source.as_str(),
                e.schedule.as_str(),
                e.user.as_str(),
                e.next_run.as_str(),
            )
        })
        .collect();
    assert_eq!(
        first,
        [
            (
                "systemd-timer",
                "anacron.timer",
                "root",
                "2026-11-16T12:33:43Z"
            ),
            ("systemd-timer", "scratch.timer", "root", ""),
        ]
    );
    assert_eq!(reply.entries[0].command, "anacron.service");
}

// Faults: a missing `systemctl` is reported (Go skips timers silently, even
// when it is also blocked), a failing one is not, or a blocked one is
// started anyway.
#[test]
fn systemctl_missing_failing_or_blocked_is_handled_as_go() {
    let bin = Bin::new();
    let missing = cron(&bin, &[]);
    assert!(
        !missing.error.contains("systemd timers"),
        "{}",
        missing.error
    );
    assert!(missing.entries.iter().all(|e| e.source == "crontab"));
    // Go looks `systemctl` up before anything else: missing and blocked is
    // still silent.
    let missing_blocked = cron(&bin, &[("LABTETHER_EXEC_BLOCKED_BINARIES", "systemctl")]);
    assert!(
        !missing_blocked.error.contains("systemd timers"),
        "{}",
        missing_blocked.error
    );

    bin.program(
        "systemctl",
        "System has not been booted with systemd\n",
        "exit 1",
    );
    let failing = cron(&bin, &[]);
    assert!(
        failing.error.starts_with("systemd timers: exit status 1"),
        "{}",
        failing.error
    );
    assert!(failing.entries.iter().all(|e| e.source == "crontab"));

    fs::remove_file(bin.0.join("systemctl.env")).unwrap();
    let blocked = cron(&bin, &[("LABTETHER_EXEC_BLOCKED_BINARIES", "systemctl")]);
    assert!(
        blocked
            .error
            .starts_with(r#"systemd timers: command "systemctl" blocked by runtime policy"#),
        "{}",
        blocked.error
    );
    assert!(
        !bin.started("systemctl"),
        "the blocked systemctl was started"
    );
}
