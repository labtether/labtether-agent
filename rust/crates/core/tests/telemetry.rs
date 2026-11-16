//! Telemetry, the offline buffer and `config.update` against the stand-in
//! Hub. Intervals are set below the Go bounds (the loader enforces those)
//! so each test runs in seconds; the samples are real readings of the test
//! machine.

mod common;

use std::time::Duration;

use common::setup::{TestDir, fast_timing, settings, start, write};
use common::{Event, Hub};
use serde_json::{Value, json};
use tokio::time::Instant;

const WAIT: Duration = Duration::from_secs(10);

fn agent_dir(name: &str) -> TestDir {
    let dir = TestDir::new(name);
    write(&dir.path("agent-token"), "agent-token");
    dir
}

/// Telemetry and heartbeats seen within `window` after now.
async fn collect_messages(hub: &mut Hub, window: Duration) -> Vec<Value> {
    let deadline = Instant::now() + window;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return seen;
        }
        match hub.next_event(left).await {
            Some(Event::Message { message, .. }) => seen.push(message),
            Some(_) => {}
            None => return seen,
        }
    }
}

fn count(messages: &[Value], kind: &str) -> usize {
    messages.iter().filter(|m| m["type"] == kind).count()
}

// Faults: telemetry is not sent, or samples taken while the Hub is away are
// lost, or kept without limit instead of the newest `telemetry_buffer`.
#[tokio::test]
async fn offline_samples_are_kept_up_to_the_limit_and_sent_after_reconnect() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    let dir = agent_dir("offline");
    let mut config = settings(&dir, &hub.ws_url(), &[]);
    config.heartbeat_interval = Duration::from_millis(200);
    config.collect_interval = Duration::from_millis(100);
    let mut timing = fast_timing();
    timing.telemetry_buffer = 5;
    let running = start(config, timing).await.unwrap();

    let telemetry = hub.wait_message("telemetry", WAIT).await;
    assert_eq!(telemetry["data"]["asset_id"], "nas01");
    for field in [
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "net_rx_bytes_per_sec",
    ] {
        assert!(telemetry["data"][field].is_number(), "{field}: {telemetry}");
    }

    hub.behaviour().refuse_upgrade = true;
    hub.drop_connections();
    hub.wait_for(WAIT, |e| {
        matches!(e, Event::Refused { status: 503, .. }).then_some(())
    })
    .await;
    // About 12 heartbeat ticks pass offline; only the newest 5 are kept.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    hub.behaviour().refuse_upgrade = false;
    hub.wait_connected(WAIT).await;
    let burst = collect_messages(&mut hub, Duration::from_millis(150)).await;
    assert_eq!(
        burst.first().map(|m| m["type"].clone()),
        Some(json!("heartbeat"))
    );
    let replayed = count(&burst, "telemetry");
    // The 5 kept samples, plus one more if a heartbeat tick fell in the window.
    assert!(
        (5..=6).contains(&replayed),
        "{replayed} telemetry messages after reconnect"
    );
    running.stop().await;
}

fn update(collect: Option<i64>, heartbeat: Option<i64>) -> Value {
    let mut data = json!({});
    if let Some(value) = collect {
        data["collect_interval_sec"] = json!(value);
    }
    if let Some(value) = heartbeat {
        data["heartbeat_interval_sec"] = json!(value);
    }
    json!({"type": "config.update", "data": data})
}

// Faults: a Hub interval change is acknowledged but not used, a value out
// of Go's bounds is applied, or a reset to 0 does not bring the start value
// back (Go's loops miss that until a restart).
#[tokio::test]
async fn config_update_changes_the_intervals_within_bounds_and_replies() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    let dir = agent_dir("config");
    let mut config = settings(&dir, &hub.ws_url(), &[]);
    config.heartbeat_interval = Duration::from_millis(300);
    config.heartbeat_pinned = false;
    let running = start(config, fast_timing()).await.unwrap();
    hub.wait_message("heartbeat", WAIT).await;

    hub.send_to_agents(&update(Some(3), Some(5)));
    let applied = hub.wait_message("config.applied", WAIT).await;
    assert_eq!(
        applied["data"],
        json!({"collect_interval_sec": 3, "heartbeat_interval_sec": 5})
    );
    let saved: Value = serde_json::from_str(&dir.read("applied-config.json").unwrap()).unwrap();
    assert_eq!(
        saved,
        json!({"collect_interval_sec": 3, "heartbeat_interval_sec": 5})
    );
    let quiet = collect_messages(&mut hub, Duration::from_millis(1500)).await;
    assert_eq!(count(&quiet, "heartbeat"), 0, "the 5 s heartbeat is in use");

    hub.send_to_agents(&update(Some(1), Some(1000)));
    let applied = hub.wait_message("config.applied", WAIT).await;
    assert_eq!(
        applied["data"],
        json!({"collect_interval_sec": 3, "heartbeat_interval_sec": 5})
    );

    hub.send_to_agents(&update(Some(0), Some(0)));
    let applied = hub.wait_message("config.applied", WAIT).await;
    // Back to the start values: collect 10 s, heartbeat 300 ms (0 whole s).
    assert_eq!(
        applied["data"],
        json!({"collect_interval_sec": 10, "heartbeat_interval_sec": 0})
    );
    assert!(
        dir.read("applied-config.json").is_none(),
        "no overrides, no file"
    );
    let resumed = collect_messages(&mut hub, Duration::from_millis(1500)).await;
    assert!(
        count(&resumed, "heartbeat") >= 3,
        "the 300 ms heartbeat is back"
    );
    running.stop().await;
}

// Fault: an interval chosen at install time is replaced by a Hub push, or
// a Hub push is applied with remote overrides turned off.
#[tokio::test]
async fn pinned_intervals_and_disabled_overrides_are_kept() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    let dir = agent_dir("pinned");
    // AGENT_HEARTBEAT_INTERVAL=5 is set by the test setup, so it is pinned.
    let config = settings(&dir, &hub.ws_url(), &[]);
    let running = start(config, fast_timing()).await.unwrap();
    hub.wait_message("heartbeat", WAIT).await;
    hub.send_to_agents(&update(Some(30), Some(60)));
    let applied = hub.wait_message("config.applied", WAIT).await;
    assert_eq!(
        applied["data"],
        json!({"collect_interval_sec": 30, "heartbeat_interval_sec": 5})
    );
    running.stop().await;

    // The first agent can have sent one more heartbeat after its
    // config.applied (on macOS its first heartbeat tick often fires after
    // the connection opens). Taken as the second agent's, it sent the next
    // update before the second agent was connected, so no agent got it and
    // the wait below timed out. Only a connection opened from here counts.
    let second = hub.next_connection();
    let dir = agent_dir("remote-off");
    let config = settings(
        &dir,
        &hub.ws_url(),
        &[("LABTETHER_ALLOW_REMOTE_OVERRIDES", "off")],
    );
    let running = start(config, fast_timing()).await.unwrap();
    hub.wait_message_since(second, "heartbeat", WAIT).await;
    hub.send_to_agents(&update(Some(30), Some(60)));
    let applied = hub.wait_message("config.applied", WAIT).await;
    assert_eq!(
        applied["data"],
        json!({"collect_interval_sec": 10, "heartbeat_interval_sec": 5})
    );
    assert!(dir.read("applied-config.json").is_none());
    running.stop().await;
}
