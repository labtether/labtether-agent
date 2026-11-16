//! The real agent driven into each state of the contract's fixtures
//! against the stand-in Hub of `crates/core/tests`, read over HTTP from the
//! real local API. Each body must pass the code rules, have the fixture's
//! field names and JSON types, and the fixture's values for every field
//! that does not depend on the clock, the host or the port.
//!
//! Two fixtures are states this agent cannot reach, and the tests say so:
//! `disconnected-no-transport` (the agent refuses to start without a Hub
//! address) and `minimal-optional-fields-absent` (it always has a start
//! time and a device key). `contract.rs` checks their bytes offline.

#[path = "../../core/tests/common/mod.rs"]
mod common;
mod support;

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use common::pki::TestPki;
use common::setup::{Running, TestDir, fast_timing, settings, start, write};
use common::{EnrollAnswer, Hub, Pending};
use data_encoding::BASE64;
use labtether_agent_core::{Agent, StartError, Timing};
use serde_json::{Value, json};
use support::{code_problems, codes, fixture, free_port, get, shape_differences};
use tokio::sync::watch;

const SECRET: &str = "local-api-test-secret";
/// Fields compared by value with the fixture.
const SAME: [&str; 16] = [
    "agent_name",
    "asset_id",
    "group_id",
    "device_fingerprint",
    "device_key_algorithm",
    "connected",
    "connection_state",
    "last_error",
    "last_error_reason",
    "enrollment_error",
    "alerts",
    "agent_version",
    "local_bind_address",
    "local_auth_enabled",
    "allow_insecure_transport",
    "update_available",
];

struct Rig {
    hub: Hub,
    dir: TestDir,
    port: u16,
    env: Vec<(String, String)>,
}

/// A TLS stand-in Hub and a state folder with the fixture's device key
/// (seed of all 7s, as the fixtures were made) and local token.
async fn rig(name: &str) -> (Rig, TestPki) {
    let pki = TestPki::new();
    let hub = Hub::start(Some(pki.acceptor())).await;
    let dir = TestDir::new(name);
    write(&dir.path("ca.crt"), &pki.ca_pem);
    let key = dir.path("device-key");
    write(&key, &format!("{}\n", BASE64.encode(&[7u8; 32])));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    write(&dir.path("local-api-secret"), &format!("{SECRET}\n"));
    let port = free_port();
    let path = |name: &str| dir.path(name).display().to_string();
    let env = vec![
        ("LABTETHER_TLS_CA_FILE".into(), path("ca.crt")),
        (
            "LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE".into(),
            path("local-api-secret"),
        ),
        ("AGENT_PORT".into(), port.to_string()),
        ("AGENT_GROUP_ID".into(), "grp-servers".into()),
        ("LABTETHER_AGENT_VERSION".into(), "v2.0.1".into()),
    ];
    (
        Rig {
            hub,
            dir,
            port,
            env,
        },
        pki,
    )
}

struct Live {
    running: Running,
    stop: watch::Sender<bool>,
    api: tokio::task::JoinHandle<()>,
    port: u16,
}

impl Rig {
    fn settings(&self, ws_url: &str, extra: &[(&str, &str)]) -> labtether_agent_config::Settings {
        let mut pairs: Vec<(&str, &str)> = self
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        pairs.extend_from_slice(extra);
        settings(&self.dir, ws_url, &pairs)
    }

    async fn start(&self, ws_url: &str, extra: &[(&str, &str)]) -> Live {
        let settings = self.settings(ws_url, extra);
        let name = settings.name.clone();
        let local = settings.local_api.clone();
        let running = start(settings, fast_timing()).await.unwrap();
        let (stop, receiver) = watch::channel(false);
        let source: Arc<dyn labtether_agent_local_api::Source> = running.agent.clone();
        let api = tokio::spawn(async move {
            labtether_agent_local_api::run(&name, &local, source, receiver).await;
        });
        Live {
            running,
            stop,
            api,
            port: self.port,
        }
    }
}

impl Live {
    /// Polls the status page until `ready` holds; panics after 10 s.
    async fn status_when(&self, ready: impl Fn(&Value) -> bool) -> Value {
        let auth = format!("Bearer {SECRET}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut last = Value::Null;
        while tokio::time::Instant::now() < deadline {
            if let Ok(answer) = get(self.port, "/agent/status", &[("Authorization", &auth)]).await
                && answer.status == 200
            {
                last = serde_json::from_str(&answer.body).unwrap();
                if ready(&last) {
                    return last;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the status did not reach the state within 10 s; last body: {last}");
    }

    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.api.await;
        self.running.stop().await;
    }
}

fn state_is(state: &'static str, last_error: Option<&'static str>) -> impl Fn(&Value) -> bool {
    move |body| body["connection_state"] == state && body["last_error"].as_str() == last_error
}

/// The contract checks. `metrics.temp_celsius` depends on the host's
/// sensors, so only its type is checked when both have it.
fn assert_matches(name: &str, body: &Value) {
    let (_, want) = fixture(name);
    assert_eq!(
        code_problems(body, &codes()),
        Vec::<String>::new(),
        "{name}: {body}"
    );
    let shape: Vec<String> = shape_differences(body, &want, "$")
        .into_iter()
        .filter(|problem| !problem.starts_with("$.metrics.temp_celsius"))
        .collect();
    assert_eq!(shape, Vec::<String>::new(), "{name}: {body}");
    for key in SAME {
        assert_eq!(body.get(key), want.get(key), "{name}: {key}");
    }
}

// Faults: the connected state, the device fingerprint, the group or the
// local API facts are reported unlike Go.
#[tokio::test]
async fn connected() {
    let (rig, _pki) = rig("st-connected").await;
    write(&rig.dir.path("agent-token"), "agent-token");
    rig.hub
        .behaviour()
        .accepted_tokens
        .insert("agent-token".into());
    let live = rig.start(&rig.hub.ws_url(), &[]).await;
    let body = live.status_when(state_is("connected", None)).await;
    assert_matches("connected", &body);
    live.stop().await;
}

// Fault: a Hub that cannot be reached shows a generic state instead of
// `transient` with Go's reason. Connecting to the broadcast address fails
// at once with ENETUNREACH on Linux, which Go reports as host_unreachable.
#[tokio::test]
async fn connecting_transient_host_unreachable() {
    let (rig, _pki) = rig("st-unreachable").await;
    write(&rig.dir.path("agent-token"), "agent-token");
    let live = rig.start("wss://255.255.255.255:9/ws/agent", &[]).await;
    let body = live
        .status_when(state_is("connecting", Some("transient")))
        .await;
    assert_matches("connecting-transient-host-unreachable", &body);
    live.stop().await;
}

// Fault: a socket waiting for approval reports connected (Go: false,
// connecting, enrollment_pending, no disconnected_at).
#[tokio::test]
async fn enrollment_pending() {
    let (rig, _pki) = rig("st-pending").await;
    let live = rig.start(&rig.hub.ws_url(), &[]).await;
    let body = live
        .status_when(state_is("connecting", Some("enrollment_pending")))
        .await;
    assert_matches("enrollment-pending", &body);
    live.stop().await;
}

// Fault: a refused agent token is not reported as auth_failed with
// token_rejected.
#[tokio::test]
async fn auth_failed_token_rejected() {
    let (rig, _pki) = rig("st-refused").await;
    write(&rig.dir.path("agent-token"), "stale-token");
    let live = rig.start(&rig.hub.ws_url(), &[]).await;
    let body = live
        .status_when(state_is("auth_failed", Some("auth_failed")))
        .await;
    assert_matches("auth-failed-token-rejected", &body);
    live.stop().await;
}

// Fault: a refused one-use token leaves the page at "connecting" through
// the fallback pending socket, or loses the Hub's words.
#[tokio::test]
async fn auth_failed_enrollment_token_rejected() {
    let (rig, _pki) = rig("st-enroll-refused").await;
    let (_, want) = fixture("auth-failed-enrollment-token-rejected");
    rig.hub.behaviour().enroll_refusal = want["enrollment_error"].as_str().unwrap().into();
    let live = rig
        .start(
            &rig.hub.ws_url(),
            &[("LABTETHER_ENROLLMENT_TOKEN", "enroll-expired")],
        )
        .await;
    let body = live
        .status_when(state_is("auth_failed", Some("enrollment_token_rejected")))
        .await;
    assert_matches("auth-failed-enrollment-token-rejected", &body);
    live.stop().await;
}

// Fault: a token that could not be saved is not shown, so the user learns
// only after a restart that the agent must enroll again. The token path is
// a folder, so the write fails even for root.
#[tokio::test]
async fn connected_token_persistence_failed() {
    let (rig, _pki) = rig("st-persist").await;
    std::fs::create_dir_all(rig.dir.path("agent-token")).unwrap();
    {
        let mut hub = rig.hub.behaviour();
        hub.enroll_group = "grp-servers".into();
        hub.enroll.insert(
            "enroll-1".into(),
            EnrollAnswer {
                agent_token: "agent-token-1".into(),
                asset_id: "nas01".into(),
            },
        );
    }
    let live = rig
        .start(
            &rig.hub.ws_url(),
            &[("LABTETHER_ENROLLMENT_TOKEN", "enroll-1")],
        )
        .await;
    let body = live
        .status_when(state_is(
            "connected",
            Some("agent_token_persistence_failed"),
        ))
        .await;
    assert_matches("connected-token-persistence-failed", &body);
    live.stop().await;
}

// Fault: an admin's rejection is not shown, or shown while connected.
#[tokio::test]
async fn enrollment_refused_hub_words() {
    let (rig, _pki) = rig("st-rejected").await;
    rig.hub.behaviour().pending = Pending::Reject;
    let live = rig.start(&rig.hub.ws_url(), &[]).await;
    let body = live
        .status_when(|b| {
            b["connection_state"] == "disconnected" && b.get("enrollment_error").is_some()
        })
        .await;
    assert_matches("enrollment-refused-hub-words", &body);
    live.stop().await;
}

// Faults: alerts from the Hub are dropped, reordered or their times
// rewritten.
#[tokio::test]
async fn alerts_with_temperature() {
    let (rig, _pki) = rig("st-alerts").await;
    write(&rig.dir.path("agent-token"), "agent-token");
    rig.hub
        .behaviour()
        .accepted_tokens
        .insert("agent-token".into());
    let live = rig.start(&rig.hub.ws_url(), &[]).await;
    live.status_when(state_is("connected", None)).await;
    let (_, want) = fixture("alerts-with-temperature");
    for alert in want["alerts"].as_array().unwrap() {
        rig.hub
            .send_to_agents(&json!({"type": "alert.notify", "data": alert}));
    }
    let body = live
        .status_when(|b| b["alerts"].as_array().is_some_and(|a| a.len() == 2))
        .await;
    assert_matches("alerts-with-temperature", &body);
    live.stop().await;
}

// Finding, not a pass: Go serves `disconnected` with no Hub address; this
// agent refuses to start. The apps never start the agent without one.
#[tokio::test]
async fn no_transport_is_a_start_error() {
    let (rig, _pki) = rig("st-no-hub").await;
    let refused = Agent::start(rig.settings("", &[]), Timing::default()).await;
    assert!(matches!(refused, Err(StartError::NoHubAddress)));
}
