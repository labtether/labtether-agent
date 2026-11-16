//! The stats schedule, with a clock the test moves. What each tick sends
//! is compared with Go in `scenario.rs`; these check the timing rules Go's
//! constants set (`collector.go`, `collector_stats.go`).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::json;

use super::Recorder;
use crate::docker::engine::{EngineApi, EngineError};
use crate::docker::stats::{MAX_SAMPLES_PER_TICK, Running, Sampler, poll_interval};

/// Answers every stats read with a sample at `cpu` percent of one CPU,
/// and records which containers were read.
struct Busy {
    cpu: RefCell<BTreeMap<String, u64>>,
    failing: RefCell<Vec<String>>,
    read: RefCell<Vec<String>>,
}

impl Busy {
    fn new() -> Self {
        Self {
            cpu: RefCell::new(BTreeMap::new()),
            failing: RefCell::new(Vec::new()),
            read: RefCell::new(Vec::new()),
        }
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.read.borrow_mut())
    }
}

impl EngineApi for Busy {
    fn get(&self, path: &str) -> Result<Vec<u8>, EngineError> {
        let id = path
            .trim_start_matches("/containers/")
            .split('/')
            .next()
            .unwrap()
            .to_owned();
        self.read.borrow_mut().push(id.clone());
        if self.failing.borrow().contains(&id) {
            return Err(EngineError::Status {
                path: path.into(),
                code: 500,
                body: String::new(),
            });
        }
        let cpu = self.cpu.borrow().get(&id).copied().unwrap_or(0);
        let sample = json!({
            "cpu_stats": {"cpu_usage": {"total_usage": 1000 + cpu}, "system_cpu_usage": 1100, "online_cpus": 1},
            "precpu_stats": {"cpu_usage": {"total_usage": 1000}, "system_cpu_usage": 1000},
            "memory_stats": {"usage": 1, "limit": 100}, "pids_stats": {"current": 1}
        });
        Ok(sample.to_string().into_bytes())
    }
}

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("c{i:02}")).collect()
}

// Fault: each tick starts from the first ID, so with every container busy
// (each due at every tick) the containers past the 24th are never sampled
// and the Hub shows no stats for them.
#[test]
fn every_container_is_sampled_when_more_than_a_tick_holds() {
    let engine = Busy::new();
    let all = ids(30);
    for id in &all {
        engine.cpu.borrow_mut().insert(id.clone(), 90);
    }
    let running = Running::new(all.clone());
    let hub = Recorder::default();
    let start = Instant::now();
    let clock = Cell::new(start);
    let mut sampler = Sampler::new(Duration::from_secs(30));
    let mut seen = std::collections::BTreeSet::new();
    for tick in 0..3u32 {
        clock.set(start + poll_interval(Duration::from_secs(30)) * tick);
        sampler.tick(&engine, &hub, &running, &|| clock.get());
        let read = engine.take();
        assert!(
            read.len() <= MAX_SAMPLES_PER_TICK,
            "tick {tick} read {}",
            read.len()
        );
        seen.extend(read);
    }
    assert_eq!(
        seen.len(),
        30,
        "never sampled: {:?}",
        all.iter()
            .filter(|id| !seen.contains(*id))
            .collect::<Vec<_>>()
    );
}

/// When `id` is read next, ticking every second from `from` for `limit`.
fn next_read(
    sampler: &mut Sampler,
    engine: &Busy,
    running: &Running,
    from: Instant,
    limit: u64,
) -> Option<u64> {
    let hub = Recorder::default();
    (1..=limit).find(|s| {
        let at = from + Duration::from_secs(*s);
        sampler.tick(engine, &hub, running, &|| at);
        !engine.take().is_empty()
    })
}

// Faults: a busy container (CPU 25 % or more) is sampled no faster, a
// quiet one is sampled as often as a busy one, or a failed read is retried
// at once (Go: busy halves the interval down to 15 s, quiet grows it by
// half up to 3 min, a failure doubles it; all at a 30 s discovery
// interval).
#[test]
fn busy_quiet_and_failing_containers_are_sampled_at_go_intervals() {
    let running = Running::new(["one".to_owned()]);
    let start = Instant::now();
    let check = |cpu: u64, fail: bool, want: &[u64]| {
        let engine = Busy::new();
        engine.cpu.borrow_mut().insert("one".into(), cpu);
        if fail {
            engine.failing.borrow_mut().push("one".into());
        }
        let mut sampler = Sampler::new(Duration::from_secs(30));
        sampler.tick(&engine, &Recorder::default(), &running, &|| start);
        engine.take();
        let mut at = start;
        for gap in want {
            assert_eq!(
                next_read(&mut sampler, &engine, &running, at, 400),
                Some(*gap),
                "cpu {cpu} fail {fail}"
            );
            at += Duration::from_secs(*gap);
        }
    };
    check(50, false, &[15, 15, 15]);
    // 30 s grows by half: 45, 67.5, 101.25, 151.875, then the 180 s
    // ceiling; read at the first whole second after each.
    check(5, false, &[45, 68, 102, 152, 180, 180]);
    check(0, true, &[60, 120, 180, 180]);
}

// Faults: stats are sent on every tick while nothing changed (a message
// every 15 s per host for nothing), or not re-sent once a discovery
// interval passed (the Hub's view goes stale).
#[test]
fn stats_are_resent_after_an_interval_and_not_before() {
    let engine = Busy::new();
    let running = Running::new(["one".to_owned()]);
    let hub = Recorder::default();
    let start = Instant::now();
    let mut sampler = Sampler::new(Duration::from_secs(30));
    let mut sends = Vec::new();
    for s in [0u64, 15, 29, 31, 46, 61] {
        let at = start + Duration::from_secs(s);
        sampler.tick(&engine, &hub, &running, &|| at);
        sends.push((s, hub.take().len()));
    }
    // Sampled at 0 (interval 45 s: next at 45), so 15 and 29 send
    // nothing; 31 s is past the 30 s interval; 46 s samples again; 61 s
    // is only 15 s after it.
    assert_eq!(sends, [(0, 1), (15, 0), (29, 0), (31, 1), (46, 1), (61, 0)]);
}
