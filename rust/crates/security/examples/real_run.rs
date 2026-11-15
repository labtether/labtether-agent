//! Runs a fixed set of commands through `CommandPolicy::run` with the
//! settings read from this process's environment, as the agent would, and
//! prints one JSON line per case. Used on the lab VM beside a Go program
//! that runs the same cases through the Go helpers.
//!
//! Usage: real_run <marker file> <sleep seconds>

use std::time::{Duration, Instant};

use labtether_agent_config::{Environment, HostFacts, load};
use labtether_agent_security::{CommandPolicy, RunError, RunRequest};
use serde_json::{Value, json};

fn report(
    case: &str,
    start: Instant,
    result: Result<labtether_agent_security::Finished, RunError>,
) {
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let line = match result {
        Err(error) => json!({"case": case, "refused": error.to_string(), "elapsed_ms": elapsed_ms}),
        Ok(done) => {
            let text = String::from_utf8_lossy(&done.output);
            json!({
                "case": case,
                "refused": Value::Null,
                "output": text.chars().take(2000).collect::<String>(),
                "output_len": done.output.len(),
                "truncated": done.truncated,
                "exit": done.status.code(),
                "signal": done.signal(),
                "timed_out": done.timed_out,
                "elapsed_ms": elapsed_ms,
            })
        }
    };
    println!("{line}");
}

fn run(policy: &CommandPolicy, case: &str, request: RunRequest) {
    let start = Instant::now();
    report(case, start, policy.run(&request));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (marker, seconds) = (args[1].clone(), args[2].clone());
    let env = Environment::from_process();
    let host = HostFacts {
        hostname: "lab".into(),
        version: "0".into(),
    };
    let settings = load(&env, &host).expect("settings").settings;
    let policy = CommandPolicy::new(&settings.command_security, &env);

    run(&policy, "allowed", RunRequest::new("uname", ["-s"]));
    run(
        &policy,
        "off-list",
        RunRequest::new("touch", [marker.as_str()]),
    );
    run(&policy, "blocked", RunRequest::new("ls", ["/"]));
    for (case, line) in [
        ("shell-refused", "cat /etc/shadow"),
        ("shell-allowed", "uname -s"),
    ] {
        let start = Instant::now();
        let result = policy
            .command_line_request(line)
            .map_err(RunError::from)
            .and_then(|request| policy.run(&request));
        report(case, start, result);
    }
    let script = format!("sleep {seconds} >/dev/null 2>&1 & echo started; sleep 2");
    let mut timeout = RunRequest::new("sh", ["-c", script.as_str()]);
    timeout.timeout = Some(Duration::from_secs(1));
    run(&policy, "timeout", timeout);
    let mut limit = RunRequest::new("sh", ["-c", "head -c 100000 /dev/zero | tr '\\0' x"]);
    limit.output_limit = 4096;
    run(&policy, "limit", limit);
    run(
        &policy,
        "env",
        RunRequest::new("sh", ["-c", "env | cut -d= -f1 | sort"]),
    );
    run(
        &policy,
        "stdin",
        RunRequest::new("sh", ["-c", "readlink /proc/self/fd/0"]),
    );
}
