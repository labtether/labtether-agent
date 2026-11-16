//! The producer's timers, as Go's `Run`: a cycle at start, then one per
//! interval; nothing while not connected.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use labtether_agent_config::web_services::WebServiceSettings;
use labtether_agent_core::Stop;
use serde_json::{Value, json};

use super::Recorder;
use crate::webservices::run;

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
    let config = WebServiceSettings {
        interval: INTERVAL,
        docker_enabled: true,
    };
    let (done, ended) = mpsc::channel();
    let (thread_sender, thread_stop) = (Arc::clone(&sender), stop.clone());
    let started = Instant::now();
    std::thread::spawn(move || {
        run(&*thread_sender, &thread_stop, &config, None, "nas01");
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
// read here (proxy, local or LAN scan) is enabled, or the Docker source is
// off when its setting is on.
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
        [json!(true), json!(false), json!(false), json!(false)]
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
