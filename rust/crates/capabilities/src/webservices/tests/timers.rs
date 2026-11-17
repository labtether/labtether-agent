//! The producer's timers, as Go's `Run`: a cycle at start, then one per
//! interval; nothing while not connected; one cycle at once per
//! `webservice.sync`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use labtether_agent_config::web_services::{PortScanSettings, WebServiceSettings};
use labtether_agent_core::Stop;
use serde_json::{Value, json};

use super::Recorder;
use crate::webservices::run;
use crate::webservices::sync::{Requests, Woken};

const INTERVAL: Duration = Duration::from_millis(1000);

/// Runs the producer until `count` reports arrived (or 8 s), then stops
/// it; the reports' arrival times from the start, and whether the thread
/// ended within 2 s of the stop.
fn reports(
    sender: Arc<Recorder>,
    count: usize,
    online_after: Duration,
) -> (Vec<Duration>, Vec<Value>, bool) {
    let stop = Stop::new();
    // The scan dials only port 1 of this machine: refused at once.
    let config = WebServiceSettings {
        interval: INTERVAL,
        docker_enabled: true,
        port_scan: PortScanSettings {
            enabled: true,
            include_listening: false,
            ports: vec![1],
        },
    };
    let (done, ended) = mpsc::channel();
    let (thread_sender, thread_stop) = (Arc::clone(&sender), stop.clone());
    let started = Instant::now();
    std::thread::spawn(move || {
        let requests = Arc::new(Requests::default());
        run(
            &*thread_sender,
            &thread_stop,
            &config,
            None,
            "nas01",
            &requests,
        );
        let _ = done.send(());
    });
    let (mut times, mut data) = (Vec::new(), Vec::new());
    while times.len() < count && started.elapsed() < Duration::from_secs(8) {
        if started.elapsed() >= online_after {
            sender.offline.store(false, Ordering::SeqCst);
        }
        for (kind, report) in sender.take() {
            assert_eq!(kind, "webservice.report");
            times.push(started.elapsed());
            data.push(report);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    stop.stop();
    let ended = ended.recv_timeout(Duration::from_secs(2)).is_ok();
    (times, data, ended)
}

// Faults: no report at start (Go's `Run` sends one as soon as it runs
// connected); reports more often than the interval; the thread outlives
// the agent's stop; the report leaves out a source or says a source not
// read here (proxy or LAN scan) is enabled, or the Docker source or the
// local scan is off when its setting is on (the setting not handed to
// the collector).
#[test]
fn reports_at_start_then_every_interval_and_stops() {
    let sender = Arc::new(Recorder::default());
    let (times, data, ended) = reports(sender, 3, Duration::ZERO);
    assert_eq!(times.len(), 3, "{times:?}");
    assert!(times[0] < Duration::from_millis(700), "{times:?}");
    for pair in times.windows(2) {
        assert!(pair[1] - pair[0] >= Duration::from_millis(900), "{times:?}");
    }
    assert!(ended, "the producer outlived the stop");
    let report = &data[0];
    assert_eq!(report["host_asset_id"], "nas01");
    let sources = &report["discovery"]["sources"];
    let enabled = |name: &str| sources[name]["enabled"].clone();
    assert_eq!(
        ["docker", "proxy", "local_scan", "lan_scan"].map(enabled),
        [json!(true), json!(false), json!(true), json!(false)]
    );
    assert_eq!(report["discovery"]["total_services"], 0);
}

// Faults: a report as soon as the agent connects, or once connected
// while the page is still starting (Go's first cycle runs as the collector
// starts, before the first connection, so its first report waits a whole
// interval; found on the lab VM, where the Rust agent's first report came
// 0.1 s after start and Go's 30 s after); a report while offline.
#[test]
fn waits_a_whole_interval_when_offline_at_start() {
    let sender = Arc::new(Recorder::default());
    sender.offline.store(true, Ordering::SeqCst);
    let (times, _, ended) = reports(sender, 1, Duration::from_millis(5));
    assert_eq!(times.len(), 1, "{times:?}");
    assert!(times[0] >= Duration::from_millis(900), "{times:?}");
    assert!(ended);
}

/// Collects reports with their times from `started` until `until`.
fn collect(sender: &Recorder, started: Instant, until: Duration, into: &mut Vec<Duration>) {
    while started.elapsed() < until {
        for (kind, _) in sender.take() {
            assert_eq!(kind, "webservice.report");
            into.push(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// Faults: a sync request runs no cycle (the Services page's sync shows
// nothing new until the next interval); it restarts the interval (Go's ticker keeps its times); it returns
// before its cycle ran (Go's worker holds its slot through the cycle);
// it never returns when the collector is not running or the agent stops
// (each such request keeps a worker slot, and at 20 the agent closes its
// connections, as Go's); the collector's wait for a request misses the
// agent's stop (the agent's shutdown waits up to an interval).
#[test]
fn sync_runs_one_cycle_per_request_at_once() {
    let sender = Arc::new(Recorder::default());
    let requests = Arc::new(Requests::default());
    let quick = Instant::now();
    requests.ask();
    assert!(quick.elapsed() < Duration::from_millis(100), "not running");
    let stop = Stop::new();
    let config = WebServiceSettings {
        interval: INTERVAL,
        docker_enabled: true,
        port_scan: PortScanSettings::default(),
    };
    let (done, ended) = mpsc::channel();
    let started = Instant::now();
    let (thread_sender, thread_stop, thread_requests) =
        (Arc::clone(&sender), stop.clone(), Arc::clone(&requests));
    std::thread::spawn(move || {
        run(
            &*thread_sender,
            &thread_stop,
            &config,
            None,
            "nas01",
            &thread_requests,
        );
        let _ = done.send(());
    });
    let mut times = Vec::new();
    collect(&sender, started, Duration::from_millis(300), &mut times);
    assert_eq!(times.len(), 1, "the report at start: {times:?}");
    let asks: Vec<_> = (0..2)
        .map(|_| {
            let requests = Arc::clone(&requests);
            let sender = Arc::clone(&sender);
            std::thread::spawn(move || {
                requests.ask();
                sender.sent.lock().unwrap().len()
            })
        })
        .collect();
    let seen: Vec<usize> = asks.into_iter().map(|a| a.join().unwrap()).collect();
    assert!(
        seen.iter().all(|n| *n >= 1),
        "returned before its cycle: {seen:?}"
    );
    collect(&sender, started, Duration::from_millis(1600), &mut times);
    assert_eq!(times.len(), 4, "{times:?}");
    assert!(times[1] < Duration::from_millis(700), "{times:?}");
    assert!(times[2] < Duration::from_millis(700), "{times:?}");
    let tick = times[3];
    assert!(
        tick >= Duration::from_millis(900) && tick < Duration::from_millis(1250),
        "the interval moved: {times:?}"
    );
    // The next tick is about 0.4 s away: the stop must not wait for it.
    stop.stop();
    assert!(ended.recv_timeout(Duration::from_millis(300)).is_ok());
    let after = Instant::now();
    requests.ask();
    assert!(
        after.elapsed() < Duration::from_millis(100),
        "after the stop"
    );
}

// Faults: requests that came together get one cycle, or a request that
// came during a cycle is served by it (Go runs a cycle per request, each
// after the one before, so a sync always sees what changed before it).
#[test]
fn each_sync_request_gets_its_own_cycle() {
    let requests = Arc::new(Requests::default());
    let stop = Stop::new();
    let _open = requests.open(&stop);
    let asks: Vec<_> = (0..2)
        .map(|_| {
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || requests.ask())
        })
        .collect();
    let soon = || Instant::now() + Duration::from_secs(2);
    assert_eq!(requests.wait(soon(), &stop), Woken::Sync);
    // Both requests are in before the first cycle ends.
    std::thread::sleep(Duration::from_millis(100));
    requests.served();
    assert_eq!(
        requests.wait(soon(), &stop),
        Woken::Sync,
        "the second cycle"
    );
    requests.served();
    for ask in asks {
        ask.join().unwrap();
    }
    let short = Instant::now() + Duration::from_millis(50);
    assert_eq!(requests.wait(short, &stop), Woken::Due);
}
