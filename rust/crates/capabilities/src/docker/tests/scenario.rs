//! The whole scenario, step by step, against the Go collector's own output
//! for the same engine answers.

use std::cell::{Cell, RefCell};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use labtether_agent_core::Stop;
use serde_json::{Value, json};

use super::engine::{Reply, StandIn};
use super::{FixtureEngine, Folder, Recorder, TESTDATA, body, compact, normalize, scenario};
use crate::docker::compose_memory::{ComposeMemory, FILE_NAME};
use crate::docker::discovery::{Inventory, RoundError};
use crate::docker::engine::{Blocking, EngineApi, EngineError, Socket};
use crate::docker::events;
use crate::docker::schedule::{Trigger, Triggers};
use crate::docker::stats::Sampler;

fn outcome(result: Result<bool, RoundError>) -> (bool, bool) {
    match result {
        Ok(changed) => (changed, false),
        Err(_) => (false, true),
    }
}

/// Go's side as compared: its Compose action fields left out (this agent
/// says it handles no Compose action), and the empty forms dropped.
fn go_side(step: &Value) -> Value {
    let mut step = step.clone();
    for message in step["sent"].as_array_mut().into_iter().flatten() {
        if let Some(data) = message["data"].as_object_mut() {
            data.remove("compose_action_version");
            data.remove("compose_endpoint_id");
        }
    }
    normalize(&step)
}

/// The event thread over a stand-in engine that sends the recorded events
/// and keeps the stream open, until `want` events reached the Hub.
fn forward_events(scenario_dir: &std::path::Path, hub: &Recorder, want: usize) {
    let fixture = &super::scenario().states["a"]["/events"];
    let stream = body(fixture, scenario_dir);
    let engine = StandIn::start(
        "events",
        vec![("/events".into(), Reply::chunks(stream, 7, true))],
    );
    let stop = Stop::new();
    let blocking = Blocking::new(Socket(engine.socket.clone()), &stop).unwrap();
    let (discovery, stats) = (Triggers::<Trigger>::new(32), Triggers::<()>::new(4));
    std::thread::scope(|scope| {
        scope.spawn(|| events::run(&blocking, hub, &stop, &discovery, &stats));
        let deadline = Instant::now() + Duration::from_secs(10);
        while hub.sent.lock().unwrap().len() < want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.stop();
    });
}

// Faults, each a field or a rule the Hub's Containers page reads: a full
// inventory missing a field, a kind (images, networks, volumes) or the
// Compose stacks, or sorted otherwise than Go; a full inventory re-sent
// when nothing changed, or not sent when images changed; a delta with the
// wrong upserts or removals, without the Compose stacks when they
// changed, or sent instead of a full inventory when most containers
// churned; a stopped Compose project missing (the memory); a failed
// images read failing the whole inventory, or a failed version read
// sending one; a new asset ID or connection not forcing a full
// inventory; anything sent while offline; engine nulls not read as empty;
// the 500-container limit not applied or the stacks not marked
// incomplete; stats computed, selected or ordered otherwise than Go (a
// failed read included); events not forwarded field for field.
#[test]
fn steps_match_go() {
    let scenario = scenario();
    let folder = Folder::new("steps", &scenario.files);
    let dir = folder.path().display().to_string();
    let engine = FixtureEngine {
        states: scenario.states.clone(),
        state: RefCell::new(String::new()),
        dir: folder.path().to_owned(),
        asked: RefCell::new(Vec::new()),
    };
    let hub = Recorder::default();
    let inventory = Inventory::new(ComposeMemory::load(Some(&folder.path().join("state"))));
    let mut sampler = Sampler::new(Duration::from_secs(30));
    let go_text = std::fs::read_to_string(format!("{TESTDATA}/go/docker-steps.json")).unwrap();
    let go: Vec<Value> = serde_json::from_str(&go_text).unwrap();
    assert_eq!(go.len(), scenario.steps.len());
    for (index, (step, want)) in scenario.steps.iter().zip(&go).enumerate() {
        if !step.state.is_empty() {
            *engine.state.borrow_mut() = step.state.clone();
        }
        if !step.asset.is_empty() {
            *hub.asset.lock().unwrap() = step.asset.clone();
        }
        if let Some(online) = step.online {
            hub.offline.store(!online, Ordering::SeqCst);
        }
        let (changed, error) = match step.call.as_str() {
            "full" => outcome(inventory.refresh_full(&engine, &hub, step.force)),
            "delta" => outcome(inventory.refresh_delta(&engine, &hub)),
            "reconnect" => {
                hub.connections.fetch_add(1, Ordering::SeqCst);
                (false, false)
            }
            "stats" => {
                sampler.tick(&engine, &hub, &inventory.running(), &Instant::now);
                (false, false)
            }
            "events" => {
                forward_events(folder.path(), &hub, step.events);
                (false, false)
            }
            "memory" => (false, false),
            other => panic!("unknown step {other}"),
        };
        let mut sent: Vec<Value> = hub
            .take()
            .into_iter()
            .map(|m| json!({"type": m["type"], "data": compact(&m["data"])}))
            .collect();
        if step.call == "memory" {
            let saved =
                std::fs::read_to_string(folder.path().join("state").join(FILE_NAME)).unwrap();
            sent.push(
                json!({"type": "memory", "data": serde_json::from_str::<Value>(&saved).unwrap()}),
            );
        }
        let got = json!({"call": step.call, "changed": changed, "error": error, "sent": sent});
        let got: Value = serde_json::from_str(&got.to_string().replace(&dir, "@DIR@")).unwrap();
        assert_eq!(
            normalize(&got),
            go_side(want),
            "step {index} ({} in state {:?}) differs from Go",
            step.call,
            step.state
        );
    }
    // Go reads the engine at unversioned paths; so does this agent.
    assert!(
        engine
            .asked
            .borrow()
            .iter()
            .all(|path| !path.starts_with("/v1"))
    );
}

/// The engine, with a new Hub connection opened (as the agent's instant
/// reconnect does) while the container list is read.
struct Reconnecting<'a> {
    engine: &'a FixtureEngine,
    hub: &'a Recorder,
    armed: Cell<bool>,
}

impl EngineApi for Reconnecting<'_> {
    fn get(&self, path: &str) -> Result<Vec<u8>, EngineError> {
        if path == "/containers/json?all=1" && self.armed.replace(false) {
            self.hub.connections.fetch_add(1, Ordering::SeqCst);
        }
        self.engine.get(path)
    }
}

// Fault: a delta built against what the old connection was sent goes out
// as the first inventory message on a new one, so a restarted Hub starts
// from a partial host (Go's reset means a new connection starts with a
// full inventory). Seen on the lab VM: the agent reconnects at once, so a
// round in flight when the connection drops does this.
#[test]
fn a_new_connection_during_a_round_gets_a_full_inventory() {
    let scenario = scenario();
    let folder = Folder::new("reconnect", &scenario.files);
    let engine = FixtureEngine {
        states: scenario.states.clone(),
        state: RefCell::new("a".into()),
        dir: folder.path().to_owned(),
        asked: RefCell::new(Vec::new()),
    };
    let hub = Recorder::default();
    let inventory = Inventory::new(ComposeMemory::load(Some(&folder.path().join("state"))));
    assert!(inventory.refresh_full(&engine, &hub, true).unwrap());
    hub.take();
    *engine.state.borrow_mut() = "b".into();
    let reconnecting = Reconnecting {
        engine: &engine,
        hub: &hub,
        armed: Cell::new(true),
    };
    assert!(inventory.refresh_delta(&reconnecting, &hub).unwrap());
    let kinds: Vec<Value> = hub.take().into_iter().map(|m| m["type"].clone()).collect();
    assert_eq!(kinds, [json!("docker.discovery")]);
}
