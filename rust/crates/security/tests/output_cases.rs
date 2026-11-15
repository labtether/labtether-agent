//! The Go agent's output cases, from the data file its own tests read. The
//! capture cases start `sh -c script` through `CommandPolicy::run`.

#![cfg(target_os = "linux")]

mod cases;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use cases::{assert_none, load, mismatch, policy};
use labtether_agent_security::{CappedBuffer, Capture, RunRequest};
use serde::Deserialize;

#[derive(Deserialize)]
struct WriterCase {
    limit: usize,
    writes: Vec<String>,
    retained: String,
    truncated: bool,
}

#[derive(Deserialize)]
struct CaptureCase {
    name: String,
    capture: String,
    script: String,
    path: Option<String>,
    limit: usize,
    timeout_ms: u64,
    length: Option<usize>,
    output: Option<String>,
    stderr: Option<String>,
    stderr_length: Option<usize>,
    #[serde(default)]
    truncated: bool,
    exit: Option<i32>,
    signal: Option<i32>,
    #[serde(default)]
    timed_out: bool,
    max_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct OutputCases {
    writer: Vec<WriterCase>,
    capture: Vec<CaptureCase>,
}

// Risk: output past the limit is kept, or a write is reported short and the
// command blocks on a full pipe.
#[test]
fn writer_cases_match_go() {
    let cases: OutputCases = load("output_cases.json");
    let mut failures = Vec::new();
    for (index, case) in cases.writer.iter().enumerate() {
        let mut buffer = CappedBuffer::new(case.limit);
        for write in &case.writes {
            if buffer.write(write.as_bytes()) != write.len() {
                failures.push(format!("writer[{index}]: short write of {write:?}"));
            }
        }
        if buffer.bytes() != case.retained.as_bytes() || buffer.truncated() != case.truncated {
            failures.push(format!(
                "writer[{index}]: kept {:?} truncated {}, want {:?} {}",
                String::from_utf8_lossy(buffer.bytes()),
                buffer.truncated(),
                case.retained,
                case.truncated
            ));
        }
    }
    assert_none(&failures);
}

fn check_capture(case: &CaptureCase, failures: &mut Vec<String>) {
    let path = case
        .path
        .clone()
        .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default());
    let policy = policy(&BTreeMap::new(), &[], &[("PATH", &path)]);
    let mut request = RunRequest::new("sh", ["-c", case.script.as_str()]);
    request.capture = if case.capture == "stdout" {
        Capture::Stdout
    } else {
        Capture::Combined
    };
    request.output_limit = case.limit;
    request.timeout = Some(Duration::from_millis(case.timeout_ms));
    let label = case.name.as_str();
    let start = Instant::now();
    let result = policy.run(&request);
    let elapsed = start.elapsed();
    if let Some(want) = &case.error {
        failures.extend(mismatch(label, result.map(|_| ()), want));
        return;
    }
    let finished = match result {
        Ok(finished) => finished,
        Err(error) => return failures.push(format!("{label}: {error}")),
    };
    let mut fail = |what: String| failures.push(format!("{label}: {what}"));
    if finished.truncated != case.truncated {
        fail(format!(
            "truncated {}, want {}",
            finished.truncated, case.truncated
        ));
    }
    if case
        .length
        .is_some_and(|want| want != finished.output.len())
    {
        fail(format!(
            "output length {}, want {:?}",
            finished.output.len(),
            case.length
        ));
    }
    if case
        .output
        .as_ref()
        .is_some_and(|want| want.as_bytes() != finished.output)
    {
        fail(format!(
            "output {:?}, want {:?}",
            String::from_utf8_lossy(&finished.output),
            case.output
        ));
    }
    if case.exit.is_some() && finished.status.code() != case.exit {
        fail(format!(
            "status {}, want exit {:?}",
            finished.status, case.exit
        ));
    }
    if case.signal.is_some() && finished.signal() != case.signal {
        fail(format!(
            "status {}, want signal {:?}",
            finished.status, case.signal
        ));
    }
    if case
        .stderr
        .as_ref()
        .is_some_and(|want| want.as_bytes() != finished.stderr)
    {
        fail(format!(
            "stderr {:?}, want {:?}",
            String::from_utf8_lossy(&finished.stderr),
            case.stderr
        ));
    }
    if case
        .stderr_length
        .is_some_and(|want| want != finished.stderr.len())
    {
        fail(format!(
            "stderr length {}, want {:?}",
            finished.stderr.len(),
            case.stderr_length
        ));
    }
    // A case that should end on its own must not reach its deadline: that
    // would mean the output was not drained.
    if finished.timed_out != case.timed_out {
        fail(format!(
            "timed out {}, want {}",
            finished.timed_out, case.timed_out
        ));
    }
    if case
        .max_ms
        .is_some_and(|max| elapsed > Duration::from_millis(max))
    {
        fail(format!(
            "took {elapsed:?}, want at most {:?} ms",
            case.max_ms
        ));
    }
}

// Risk: a started command's output is not drained, cut or reported the way
// the Go helpers do, or a timeout does not stop it.
#[test]
fn capture_cases_match_go() {
    let cases: OutputCases = load("output_cases.json");
    let mut failures = Vec::new();
    for case in &cases.capture {
        check_capture(case, &mut failures);
    }
    assert_none(&failures);
}
