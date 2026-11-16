//! The live log stream: Go's batching, dropping and restart rules with a
//! made-up source and Hub, then `journalctl --follow` itself with fake
//! programs through the real command rules.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labtether_agent_core::outbox::SendError;
use labtether_agent_core::{HubSender, Stop};
use labtether_agent_platform::tool_output::journal::{JournalEntry, MAX_JOURNAL_LINE};
use labtether_protocol::{LogBatchData, Message};

use super::fakebin::{FakeBin, serial};
use crate::logs::stream::{StreamEnd, journal, run};

const FIXTURE: &[u8] = include_bytes!("../../../platform/testdata/journal-lines.jsonl");

/// A Hub that records what is sent, and can be offline.
#[derive(Default)]
struct Recorder {
    offline: AtomicBool,
    sent: Mutex<Vec<Message>>,
}

impl HubSender for Recorder {
    fn connected(&self) -> bool {
        !self.offline.load(Ordering::SeqCst)
    }
    fn asset_id(&self) -> String {
        "nas01".into()
    }
    fn send(&self, message: &Message) -> Result<(), SendError> {
        if !self.connected() {
            return Err(SendError::Closed);
        }
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
}

impl Recorder {
    fn batches(&self) -> Vec<LogBatchData> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|m| {
                assert_eq!((m.r#type.as_str(), m.id.as_str()), ("log.batch", ""));
                m.decode().unwrap()
            })
            .collect()
    }
}

fn entry(n: usize) -> JournalEntry {
    JournalEntry {
        timestamp: "2026-11-16T03:00:00Z".into(),
        level: "info",
        message: format!("m{n}"),
        source: "sshd".into(),
    }
}

/// Runs the stream once over `steps`: `(seconds after start, entry or a
/// change of connection)`, then the source ends cleanly.
fn stream(hub: &Recorder, steps: &[(f64, Option<usize>, Option<bool>)]) {
    let start = Instant::now();
    let clock = Mutex::new(start);
    let source = |_: &Stop, emit: &mut dyn FnMut(JournalEntry)| {
        for (at, item, offline) in steps {
            *clock.lock().unwrap() = start + Duration::from_secs_f64(*at);
            if let Some(offline) = offline {
                hub.offline.store(*offline, Ordering::SeqCst);
            }
            if let Some(n) = item {
                emit(entry(*n));
            }
        }
        Ok(())
    };
    run(hub, &Stop::new(), &source, &|| *clock.lock().unwrap());
}

fn messages(batch: &LogBatchData) -> Vec<String> {
    batch.entries.iter().map(|e| e.message.clone()).collect()
}

// Faults: batches hold more or fewer than Go's 50; the rest is lost when
// the source ends; a batch is sent on a timer (Go sends only when an entry
// arrives more than 2 s after the last send, the entry included); the
// asset ID or the entry fields are not Go's.
#[test]
fn batches_follow_go() {
    let hub = Recorder::default();
    let mut steps: Vec<_> = (0..120).map(|n| (0.0, Some(n), None)).collect();
    steps.push((2.0, Some(120), None));
    steps.push((2.5, Some(121), None));
    steps.push((4.6, Some(122), None));
    steps.push((4.7, Some(123), None));
    stream(&hub, &steps);
    let sizes: Vec<usize> = hub.batches().iter().map(|b| b.entries.len()).collect();
    // 50, 50; 20 + #120 at 2.0 s (not after 2 s) + #121 at 2.5 s (after);
    // #122 at 4.6 s (after 4.5); #123 sent when the source ends.
    assert_eq!(sizes, [50, 50, 22, 1, 1]);
    let batches = hub.batches();
    assert_eq!(messages(&batches[3]), ["m122"]);
    assert_eq!(batches[0].asset_id, "nas01");
    assert_eq!(
        serde_json::to_value(&batches[0].entries[0]).unwrap(),
        serde_json::json!({"asset_id": "", "timestamp": "2026-11-16T03:00:00Z",
            "level": "info", "message": "m0", "source": "sshd"})
    );
}

// Faults: entries read while no connection is open are kept and sent
// later (Go drops them). As in Go, an entry already waiting in the batch
// when the connection drops goes out with the next batch.
#[test]
fn offline_entries_are_dropped() {
    let hub = Recorder::default();
    stream(
        &hub,
        &[
            (0.0, Some(1), None),
            (0.1, None, Some(true)),
            (0.2, Some(2), None),
            (2.5, Some(3), None),
            (2.6, None, Some(false)),
            (2.7, Some(4), None),
            (5.0, Some(5), None),
        ],
    );
    let all: Vec<Vec<String>> = hub.batches().iter().map(messages).collect();
    assert_eq!(all, [vec!["m1", "m4"], vec!["m5"]]);
}

// Faults: a failed run is not started again, or not after Go's waits (1 s,
// then 2 s); a clean end or a missing journalctl is retried; the stop does
// not end a wait.
#[test]
fn failures_restart_after_go_waits() {
    let hub = Recorder::default();
    let calls = AtomicUsize::new(0);
    let started = Instant::now();
    let source =
        |_: &Stop, _: &mut dyn FnMut(JournalEntry)| match calls.fetch_add(1, Ordering::SeqCst) {
            0 | 1 => Err(StreamEnd::Failed(
                "journalctl stream failed: exit status 1".into(),
            )),
            _ => Ok(()),
        };
    run(&hub, &Stop::new(), &source, &Instant::now);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(3) && took < Duration::from_secs(5),
        "{took:?}"
    );

    calls.store(0, Ordering::SeqCst);
    let unsupported = |_: &Stop, _: &mut dyn FnMut(JournalEntry)| {
        calls.fetch_add(1, Ordering::SeqCst);
        Err(StreamEnd::Unsupported)
    };
    run(&hub, &Stop::new(), &unsupported, &Instant::now);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let stop = Stop::new();
    let stopper = stop.clone();
    let failing = |_: &Stop, _: &mut dyn FnMut(JournalEntry)| {
        stopper.stop();
        Err(StreamEnd::Failed("x".into()))
    };
    let started = Instant::now();
    run(&hub, &stop, &failing, &Instant::now);
    assert!(started.elapsed() < Duration::from_millis(500));
}

fn follow(
    bin: &FakeBin,
    blocked: &[&str],
    stop: &Stop,
) -> (Result<(), StreamEnd>, Vec<JournalEntry>) {
    let mut got = Vec::new();
    let result = journal(&bin.policy(blocked), stop, &mut |entry| got.push(entry));
    (result, got)
}

fn journalctl(body: &str) -> FakeBin {
    let bin = FakeBin::new();
    bin.file("fixture.jsonl", FIXTURE)
        .program("journalctl", body);
    bin
}

// Faults: journalctl runs with other arguments than Go's (full names), or
// with the agent's whole environment; a clean exit, an error exit or a
// refusal is reported in other words than Go's; a missing journalctl is
// retried.
#[test]
fn journal_runs_report_as_go() {
    let _serial = serial();
    let stop = Stop::new();
    let bin = journalctl("/bin/cat \"$D/fixture.jsonl\"");
    let (result, got) = follow(&bin, &[], &stop);
    assert_eq!((result, got.len()), (Ok(()), 18));
    assert_eq!(
        bin.calls("journalctl").unwrap(),
        ["--follow --output=json --lines=0"]
    );
    assert!(
        bin.env("journalctl")
            .iter()
            .all(|v| !v.starts_with("LABTETHER_SECRET"))
    );

    let bin = journalctl("/bin/cat \"$D/fixture.jsonl\"; exit 3");
    let (result, got) = follow(&bin, &[], &stop);
    assert_eq!(
        result,
        Err(StreamEnd::Failed(
            "journalctl stream failed: exit status 3".into()
        ))
    );
    assert_eq!(got.len(), 18);

    let bin = journalctl("exit 0");
    let (result, _) = follow(&bin, &["journalctl"], &stop);
    assert_eq!(result, Err(StreamEnd::Failed(
        "failed to build journalctl stream command: command \"journalctl\" blocked by runtime policy".into()
    )));
    assert!(bin.calls("journalctl").is_none());

    let (result, _) = follow(&FakeBin::new(), &[], &stop);
    assert_eq!(result, Err(StreamEnd::Unsupported));
}

// Faults: stopping the agent leaves journalctl running (Go kills it with
// its context), or the stream does not return.
#[test]
fn stop_ends_a_following_journalctl() {
    let _serial = serial();
    let bin = journalctl("echo $$ > \"$D/pid\"; /bin/cat \"$D/fixture.jsonl\"; exec /bin/sleep 60");
    let stop = Stop::new();
    let stopper = stop.clone();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let thread = std::thread::spawn(move || {
        let started = Instant::now();
        while counter.load(Ordering::SeqCst) < 18 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        stopper.stop();
    });
    let started = Instant::now();
    let result = journal(&bin.policy(&[]), &stop, &mut |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(seen.load(Ordering::SeqCst), 18);
    assert!(started.elapsed() < Duration::from_secs(5));
    let pid = std::fs::read_to_string(bin.dir.join("pid")).unwrap();
    let alive = std::path::Path::new(&format!("/proc/{}", pid.trim())).exists();
    assert!(!alive, "journalctl still runs");
}

/// A journalctl JSON line of exactly `n` bytes before its newline.
fn journal_line(n: usize) -> Vec<u8> {
    let mut line = b"{\"MESSAGE\":\"".to_vec();
    line.resize(n - 2, b'a');
    line.extend_from_slice(b"\"}\n");
    line
}

// Faults: a line of 256 KiB or more stops the stream (Go's did, until the
// agent restarted: its scanner stopped and journalctl was never read
// again), or ends journalctl and loses what follows, whether the line ends
// within the reader's limit or long after it; a line one byte under the
// limit is dropped; the line after a skipped one waits for the next.
#[test]
fn a_line_too_long_is_skipped_and_the_stream_goes_on() {
    let _serial = serial();
    let mut output = b"{\"MESSAGE\":\"before\"}\n".to_vec();
    output.extend(journal_line(MAX_JOURNAL_LINE - 1));
    output.extend(journal_line(MAX_JOURNAL_LINE));
    // Longer than the reader holds: skipped while it is still arriving.
    output.extend(journal_line(3 * MAX_JOURNAL_LINE));
    output.extend_from_slice(b"{\"MESSAGE\":\"after\"}\n");
    let bin = FakeBin::new();
    bin.file("long.jsonl", &output).program(
        "journalctl",
        "/bin/cat \"$D/long.jsonl\"; exec /bin/sleep 30",
    );
    let stop = Stop::new();
    let stopper = stop.clone();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let thread = std::thread::spawn(move || {
        let started = Instant::now();
        while counter.load(Ordering::SeqCst) < 3 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        stopper.stop();
    });
    let mut got = Vec::new();
    let result = journal(&bin.policy(&[]), &stop, &mut |entry| {
        seen.fetch_add(1, Ordering::SeqCst);
        got.push(entry.message);
    });
    thread.join().unwrap();
    assert_eq!(result, Ok(()));
    let long = MAX_JOURNAL_LINE - 1 - b"{\"MESSAGE\":\"\"}".len();
    let summary: Vec<String> = got
        .iter()
        .map(|m| {
            if m.len() > 16 {
                format!("{} bytes", m.len())
            } else {
                m.clone()
            }
        })
        .collect();
    assert_eq!(
        summary,
        [
            "before".to_owned(),
            format!("{long} bytes"),
            "after".to_owned()
        ]
    );
}
