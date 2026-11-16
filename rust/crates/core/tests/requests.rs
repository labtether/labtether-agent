//! Feature requests against the stand-in Hub: the typed reply, the worker
//! bound and the token check, with a made-up handler for `disk.list` so no
//! real feature is needed here.

mod common;

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use common::setup::{TestDir, fast_timing, settings, start_with, write};
use common::{Event, Hub};
use labtether_agent_core::Features;
use labtether_protocol::{DiskListData, DiskListedData, MSG_DISK_LIST, MSG_DISK_LISTED};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(10);

/// A gate the handler waits on until the test opens it, or 15 s at most so
/// a broken build that runs handlers on the read loop fails instead of
/// hanging the test run.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let open = self.open.lock().unwrap();
        let _ = self
            .changed
            .wait_timeout_while(open, Duration::from_secs(15), |open| !*open)
            .unwrap();
    }

    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

fn request_id(request: &DiskListData) -> &str {
    &request.request_id
}

fn disk_features(gate: Option<Arc<Gate>>) -> Features {
    let mut features = Features::new();
    features.on_request(
        MSG_DISK_LIST,
        MSG_DISK_LISTED,
        request_id,
        move |request: DiskListData| {
            if let Some(gate) = &gate {
                gate.wait();
            }
            DiskListedData {
                request_id: request.request_id,
                error: "made up".into(),
                ..DiskListedData::default()
            }
        },
    );
    features
}

fn disk_list(id: &str) -> Value {
    json!({"type": "disk.list", "id": "envelope", "data": {"request_id": id}})
}

async fn agent_with(
    hub: &Hub,
    name: &str,
    token: &str,
    workers: usize,
    features: Features,
) -> (common::setup::Running, TestDir) {
    hub.behaviour().accepted_tokens.insert(token.into());
    let dir = TestDir::new(name);
    write(&dir.path("agent-token"), token);
    let config = settings(&dir, &hub.ws_url(), &[]);
    let mut timing = fast_timing();
    timing.request_workers = workers;
    timing.read_deadline = Duration::from_secs(5);
    let running = start_with(config, timing, features).await.unwrap();
    (running, dir)
}

/// The next reply of `kind`, or `None` when none comes within `limit`.
async fn reply_within(hub: &mut Hub, kind: &str, limit: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match hub.next_event(left).await? {
            Event::Message { message, .. } if message["type"] == kind => return Some(message),
            _ => {}
        }
    }
}

// Faults: the reply carries the envelope ID instead of `request_id`, the
// wrong type or payload; a request that does not decode gets a reply (Go
// sends none).
#[tokio::test]
async fn typed_reply_uses_the_request_id_and_bad_requests_get_none() {
    let mut hub = Hub::start(None).await;
    let (running, _dir) = agent_with(&hub, "typed", "agent-token", 20, disk_features(None)).await;
    hub.wait_connected(WAIT).await;
    hub.send_to_agents(&json!({"type": "disk.list", "data": {"request_id": 5}}));
    assert!(
        reply_within(&mut hub, "disk.listed", Duration::from_millis(800))
            .await
            .is_none()
    );
    hub.send_to_agents(&disk_list("req-1"));
    let reply = reply_within(&mut hub, "disk.listed", WAIT).await.unwrap();
    assert_eq!(reply["id"], "req-1");
    assert_eq!(reply["data"]["request_id"], "req-1");
    assert_eq!(reply["data"]["error"], "made up");
    running.stop().await;
}

// Faults: the heartbeat leaves out `agent_capability_mode=explicit` (the
// Hub then offers every page, as to a Go agent), leaves out the word of a
// registered handler (the Hub refuses a page the agent answers), names a
// page with no handler, sends an edition this build is not, or fills the
// `capabilities` list (terminal, files, desktop, power, WebRTC).
#[tokio::test]
async fn heartbeat_names_exactly_the_registered_requests() {
    let mut hub = Hub::start(None).await;
    let (running, _dir) = agent_with(&hub, "words", "agent-token", 20, disk_features(None)).await;
    let heartbeat = hub.wait_message("heartbeat", WAIT).await;
    let data = &heartbeat["data"];
    let metadata = data["metadata"].as_object().unwrap();
    let words: Vec<(&str, &str)> = metadata
        .iter()
        .filter(|(key, _)| key.starts_with("cap_") || key.starts_with("agent_ca"))
        .map(|(key, value)| (key.as_str(), value.as_str().unwrap()))
        .collect();
    assert_eq!(
        words,
        [("agent_capability_mode", "explicit"), ("cap_disks", "list")]
    );
    assert!(!metadata.contains_key("agent_edition"), "{metadata:?}");
    assert!(data.get("capabilities").is_none(), "{data}");
    running.stop().await;
}

// Faults: a handler runs on the read loop (the ping during the blocked
// handlers gets no pong), there is no bound (the request past the limit
// runs), the limit does not close the connection as Go does, or slots are
// not given back (the request on the next connection gets no reply).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workers_are_bounded_and_keep_the_read_loop_free() {
    let mut hub = Hub::start(None).await;
    let gate = Arc::new(Gate::default());
    let (running, _dir) = agent_with(
        &hub,
        "bound",
        "agent-token",
        2,
        disk_features(Some(gate.clone())),
    )
    .await;
    let agent = running.agent.clone();
    hub.wait_connected(WAIT).await;
    hub.send_to_agents(&disk_list("a"));
    hub.send_to_agents(&disk_list("b"));
    hub.send_to_agents(&json!({"type": "ping"}));
    assert!(
        reply_within(&mut hub, "pong", WAIT).await.is_some(),
        "the read loop is blocked"
    );
    hub.send_to_agents(&disk_list("c"));
    hub.wait_for(WAIT, |event| {
        matches!(event, Event::Closed { .. }).then_some(())
    })
    .await;
    hub.wait_connected(WAIT).await;
    gate.open();
    let deadline = tokio::time::Instant::now() + WAIT;
    while agent.workers_running() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(agent.workers_running(), 0);
    hub.send_to_agents(&disk_list("d"));
    let reply = reply_within(&mut hub, "disk.listed", WAIT).await.unwrap();
    assert_eq!(
        reply["id"], "d",
        "a reply from the closed connection came through"
    );
    running.stop().await;
}

fn jwt(claims: &Value) -> String {
    let payload = data_encoding::BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
    format!("eyJhbGciOiJub25lIn0.{payload}.c2ln")
}

// Faults: the token check is skipped for feature requests (a token that
// allows only the terminal reads the disk list), or the check refuses a
// token that holds a listed capability.
#[tokio::test]
async fn the_token_check_runs_before_feature_handlers() {
    let mut hub = Hub::start(None).await;
    let token = jwt(&json!({"capabilities": ["agent.terminal"]}));
    let (running, _dir) = agent_with(&hub, "deny", &token, 20, disk_features(None)).await;
    hub.wait_connected(WAIT).await;
    hub.send_to_agents(&disk_list("denied"));
    hub.send_to_agents(&json!({"type": "ping"}));
    assert!(reply_within(&mut hub, "pong", WAIT).await.is_some());
    assert!(
        reply_within(&mut hub, "disk.listed", Duration::from_millis(800))
            .await
            .is_none()
    );
    running.stop().await;

    let mut hub = Hub::start(None).await;
    let token = jwt(&json!({"scope": "agent.terminal agent.inspect"}));
    let (running, _dir) = agent_with(&hub, "allow", &token, 20, disk_features(None)).await;
    hub.wait_connected(WAIT).await;
    hub.send_to_agents(&disk_list("allowed"));
    let reply = reply_within(&mut hub, "disk.listed", WAIT).await.unwrap();
    assert_eq!(reply["id"], "allowed");
    running.stop().await;
}
