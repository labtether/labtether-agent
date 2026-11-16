//! What `CommandPolicy::run` promises on a real system beyond the Go cases:
//! nothing starts when refused, a timeout leaves no process of the command
//! behind, a held pipe cannot hold the caller past `wait_delay`, and the
//! child sees only the sanitized environment.

#![cfg(target_os = "linux")]

mod cases;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use cases::policy;
use labtether_agent_platform::process::kill_group;
use labtether_agent_security::{RunError, RunRequest};

fn path() -> String {
    std::env::var("PATH").unwrap_or_default()
}

/// The process group of `pid`, from `/proc/<pid>/stat`, or `None` once the
/// process is gone or a zombie.
fn live_group(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    (fields.first() != Some(&"Z")).then(|| fields.get(2)?.parse().ok())?
}

fn gone_within(pid: u32, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if live_group(pid).is_none() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

// Fault: the program is checked after it has started, so a refused command
// still runs.
#[test]
fn a_refused_program_never_starts() {
    let marker = std::env::temp_dir().join(format!("lt-security-marker-{}", std::process::id()));
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path())]);
    let request = RunRequest::new("touch", [marker.to_str().unwrap()]);
    let error = policy.run(&request).unwrap_err();
    assert_eq!(error.to_string(), "command \"touch\" is not allowlisted");
    assert!(matches!(error, RunError::Refused(_)));
    assert!(!Path::new(&marker).exists(), "touch ran");
}

// Fault: a timeout stops only the direct child (as Go's plain helpers did
// before 2026-11-16), so a background process of the command keeps running.
#[test]
fn a_timeout_stops_the_whole_process_group() {
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path())]);
    let script = "sleep 30 >/dev/null 2>&1 & echo $!; sleep 30";
    let mut request = RunRequest::new("sh", ["-c", script]);
    request.timeout = Some(Duration::from_millis(300));
    let start = Instant::now();
    let finished = policy.run(&request).unwrap();
    let elapsed = start.elapsed();
    let background: u32 = String::from_utf8_lossy(&finished.output)
        .trim()
        .parse()
        .unwrap();
    let stopped = gone_within(background, Duration::from_secs(2));
    if !stopped && let Some(group) = live_group(background) {
        let _ = kill_group(group);
    }
    assert!(
        stopped,
        "background process {background} still running after the timeout"
    );
    assert!(finished.timed_out);
    assert_eq!(finished.signal(), Some(9));
    assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
}

// Fault: `wait_delay` is ignored, so a background process that keeps the
// output pipe open holds the caller until it ends.
#[test]
fn wait_delay_bounds_a_held_pipe() {
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path())]);
    let mut request = RunRequest::new("sh", ["-c", "sleep 5 & echo started"]);
    request.wait_delay = Some(Duration::from_millis(200));
    let start = Instant::now();
    let finished = policy.run(&request).unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "took {:?}",
        start.elapsed()
    );
    assert!(finished.output_held);
    assert!(finished.status.success() && !finished.succeeded());
    assert_eq!(finished.output, b"started\n");
}

// Fault: the child gets the agent's environment, so a token or setting
// reaches it; or it is started with a path as its name ($0).
#[test]
fn the_child_sees_only_the_sanitized_environment() {
    let path = path();
    let extra = [
        ("PATH", path.as_str()),
        ("HOME", "/home/demo"),
        ("LABTETHER_API_TOKEN", "agent-secret"),
        ("FOO_SECRET", "x"),
    ];
    let mut env = BTreeMap::new();
    env.insert(
        "LABTETHER_EXEC_BLOCKED_BINARIES".to_owned(),
        "ls".to_owned(),
    );
    let policy = policy(&env, &[], &extra);
    let request = RunRequest::new("sh", ["-c", "echo \"0=$0\"; env"]);
    let finished = policy.run(&request).unwrap();
    let text = String::from_utf8(finished.output).unwrap();
    let mut keys: Vec<&str> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, _)| k)
        .collect();
    keys.sort_unstable();
    assert!(text.starts_with("0=sh\n"), "{text}");
    assert!(text.contains("\nHOME=/home/demo\n"), "{text}");
    assert!(text.contains(&format!("\nPATH={path}\n")), "{text}");
    for secret in [
        "LABTETHER_API_TOKEN",
        "FOO_SECRET",
        "LABTETHER_EXEC_BLOCKED_BINARIES",
    ] {
        assert!(
            !keys.contains(&secret),
            "{secret} reached the child: {keys:?}"
        );
    }
}

// Fault: with the default request a command that ends but leaves a
// background process holding its output (a started daemon) keeps the
// caller waiting until that process ends. Go bounds this with a 1 s
// WaitDelay on the remote command path and, on Linux and macOS, in its plain
// helpers.
#[test]
fn the_default_request_does_not_wait_for_a_background_holder() {
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path())]);
    let request = RunRequest::new("sh", ["-c", "sleep 6 & echo started"]);
    let start = Instant::now();
    let finished = policy.run(&request).unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "took {:?}",
        start.elapsed()
    );
    assert!(finished.output_held);
    assert_eq!(finished.output, b"started\n");
}

// Fault: after a timeout the drain has no bound, so a process that left the
// command's group (setsid) and still holds the pipe keeps the caller
// waiting, even with `wait_delay: None`.
#[test]
fn a_timeout_bounds_the_drain_even_without_a_wait_delay() {
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path())]);
    let mut request = RunRequest::new("sh", ["-c", "setsid sleep 6 & sleep 30"]);
    request.timeout = Some(Duration::from_millis(300));
    request.wait_delay = None;
    let start = Instant::now();
    let finished = policy.run(&request).unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "took {:?}",
        start.elapsed()
    );
    assert!(finished.timed_out && finished.output_held);
}

// Fault: when the wait delay runs out the reader thread keeps the pipe open
// (and its buffer alive) after `run` returns, until the holder ends. Go
// closes the pipe; here the reader is stopped and joined, so a later write
// by the holder fails.
#[test]
fn a_held_pipe_is_closed_when_run_returns() {
    let marker = std::env::temp_dir().join(format!("lt-security-closed-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let script = format!(
        "(trap '' PIPE; sleep 1; echo late || touch {}) & echo started",
        marker.display()
    );
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path())]);
    let mut request = RunRequest::new("sh", ["-c", script.as_str()]);
    request.wait_delay = Some(Duration::from_millis(200));
    let finished = policy.run(&request).unwrap();
    assert!(finished.output_held);
    let start = Instant::now();
    while !marker.exists() && start.elapsed() < Duration::from_secs(4) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let closed = marker.exists();
    let _ = std::fs::remove_file(&marker);
    assert!(
        closed,
        "the holder could still write: the pipe outlived run"
    );
}
