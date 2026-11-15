//! The enrollment state machine and commit invariants from the protocol's
//! `connection-enrollment-v1.json`, against a stand-in Hub:
//!
//! - unconfigured --submit_one_use_token--> enrolling
//!   --durable_credential_committed--> connected_durable
//! - connected_durable --credential_revoked--> auth_failed
//!   --submit_reenrollment_token--> reenrolling --committed--> connected_durable
//! - connected_durable --operator_stop--> stopped
//!
//! Invariants checked here: canonical_asset_id_matches_hub,
//! device_key_is_preserved, durable_credential_is_private,
//! one_use_token_is_removed_after_commit. failed_commit_rolls_back is a unit
//! test in `src/tests.rs`, because it needs a write that fails.

mod common;

use std::time::Duration;

use common::setup::{TestDir, fast_timing, settings, start, write};
use common::{EnrollAnswer, Event, Hub, Pending};
use data_encoding::{BASE64, HEXLOWER};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use labtether_agent_core::identity;
use serde_json::Value;
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(10);

fn answer(token: &str, asset: &str) -> EnrollAnswer {
    EnrollAnswer {
        agent_token: token.into(),
        asset_id: asset.into(),
    }
}

/// Checks a token-enrollment proof the way the Hub does.
fn token_proof_valid(body: &Value, version: &str, subject: &str, token: &str) -> bool {
    let field = |name: &str| body[name].as_str().unwrap_or_default().to_owned();
    let public: [u8; 32] = BASE64
        .decode(field("device_public_key").as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let signature: [u8; 64] = BASE64
        .decode(field("device_signature").as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let token_hash = HEXLOWER.encode(&Sha256::digest(token.as_bytes()));
    let payload = format!(
        "labtether-token-enrollment-proof-{version}|{subject}|{token_hash}|{}",
        field("device_fingerprint")
    );
    field("device_proof_version") == version
        && field("device_fingerprint") == identity::fingerprint(&public)
        && VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(payload.as_bytes(), &Signature::from_bytes(&signature))
            .is_ok()
}

// Faults caught: the token is sent to the wrong place or unsigned; the
// credential is world-readable; the one-use token stays on disk; the device
// key is replaced; the Hub's asset ID is not used; a restart enrolls again.
#[tokio::test]
async fn one_use_token_enrolls_commits_and_survives_restart() {
    let mut hub = Hub::start(None).await;
    hub.behaviour()
        .enroll
        .insert("enroll-1".into(), answer("agent-token-1", "nas01-hub"));
    let dir = TestDir::new("enroll");
    let token_file = dir.path("enroll.token");
    write(&token_file, "enroll-1\n");
    let token_path = token_file.display().to_string();
    let settings = settings(
        &dir,
        &hub.ws_url(),
        &[("LABTETHER_ENROLLMENT_TOKEN_FILE", &token_path)],
    );
    identity::ensure(&settings).unwrap();
    let key_before = dir.read("device-key").unwrap();

    let running = start(settings.clone(), fast_timing()).await.unwrap();
    let body = hub
        .wait_for(WAIT, |e| match e {
            Event::Enroll { body } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(body["hostname"], "nas01");
    assert_eq!(body["platform"], "linux");
    assert!(token_proof_valid(&body, "v1", "nas01", "enroll-1"));

    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["authorization"], "Bearer agent-token-1");
    assert_eq!(headers["x-asset-id"], "nas01-hub");
    assert!(!headers.contains_key("x-request-enrollment"));
    let heartbeat = hub.wait_message("heartbeat", WAIT).await;
    assert_eq!(heartbeat["data"]["asset_id"], "nas01-hub");

    assert_eq!(dir.read("agent-token").as_deref(), Some("agent-token-1\n"));
    assert_eq!(dir.mode("agent-token"), 0o600);
    let state: Value = serde_json::from_str(&dir.read("enrollment-state.json").unwrap()).unwrap();
    assert_eq!(state["asset_id"], "nas01-hub");
    assert_eq!(dir.mode("enrollment-state.json"), 0o600);
    assert!(
        !token_file.exists(),
        "the used one-use token file is removed"
    );
    assert_eq!(dir.read("device-key").unwrap(), key_before);
    assert_eq!(dir.mode("device-key"), 0o600);

    // operator_stop: the agent closes its socket and its loop ends.
    running.stop().await;
    hub.wait_for(WAIT, |e| matches!(e, Event::Closed { .. }).then_some(()))
        .await;

    // Restart: the saved credential is used and nothing is enrolled again.
    let running = start(settings, fast_timing()).await.unwrap();
    let headers = hub
        .wait_for(WAIT, |e| match e {
            Event::Enroll { .. } => panic!("a restart must not enroll again"),
            Event::Connected { headers, .. } => Some(headers.clone()),
            _ => None,
        })
        .await;
    assert_eq!(headers["authorization"], "Bearer agent-token-1");
    assert_eq!(headers["x-asset-id"], "nas01-hub");
    running.stop().await;
}

// Fault: an agent whose token was revoked retries forever instead of using
// the staged re-enrollment token, or re-enrolls with a proof the Hub cannot
// tie to the existing asset (v2, bound to the Hub's asset ID).
#[tokio::test]
async fn revoked_credential_re_enrolls_with_the_staged_token() {
    let mut hub = Hub::start(None).await;
    hub.behaviour()
        .enroll
        .insert("re-enroll-1".into(), answer("agent-token-2", "nas01"));
    let dir = TestDir::new("reenroll");
    write(&dir.path("agent-token"), "revoked-token\n");
    let token_file = dir.path("reenroll.token");
    write(&token_file, "re-enroll-1");
    let token_path = token_file.display().to_string();
    let settings = settings(
        &dir,
        &hub.ws_url(),
        &[("LABTETHER_ENROLLMENT_TOKEN_FILE", &token_path)],
    );

    let running = start(settings, fast_timing()).await.unwrap();
    let mut refused = 0;
    let body = hub
        .wait_for(WAIT, |e| match e {
            Event::Refused { headers, .. } => {
                assert_eq!(headers["authorization"], "Bearer revoked-token");
                refused += 1;
                None
            }
            Event::Enroll { body } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(refused, 3, "re-enrollment starts at the third refusal");
    assert!(token_proof_valid(&body, "v2", "nas01", "re-enroll-1"));
    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["authorization"], "Bearer agent-token-2");
    assert_eq!(dir.read("agent-token").as_deref(), Some("agent-token-2\n"));
    assert!(!token_file.exists());
    running.stop().await;
}

// Faults: the pending socket sends anything but the proof; the proof does not
// verify; the approved token is not saved or not used.
#[tokio::test]
async fn pending_enrollment_proves_the_key_and_uses_the_approved_token() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().pending = Pending::Approve {
        token: "approved-1".into(),
        asset_id: "nas01-approved".into(),
    };
    let dir = TestDir::new("pending");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();

    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["x-request-enrollment"], "true");
    assert_eq!(headers["x-hostname"], "nas01.example.com");
    assert_eq!(headers["x-device-key-alg"], "ed25519");
    let fingerprint = dir.read("device-fingerprint").unwrap();
    assert_eq!(headers["x-device-fingerprint"], fingerprint.trim());
    assert!(!headers.contains_key("authorization"));

    let mut pending_messages = Vec::new();
    let valid = hub
        .wait_for(WAIT, |e| match e {
            Event::Message { message, .. } => {
                pending_messages.push(message["type"].clone());
                None
            }
            Event::Proof { valid } => Some(*valid),
            _ => None,
        })
        .await;
    assert!(valid, "the proof verifies against the device key");
    assert_eq!(pending_messages, ["enrollment.proof"]);

    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["authorization"], "Bearer approved-1");
    let heartbeat = hub.wait_message("heartbeat", WAIT).await;
    assert_eq!(heartbeat["data"]["asset_id"], "nas01-approved");
    assert_eq!(dir.read("agent-token").as_deref(), Some("approved-1\n"));
    assert_eq!(dir.mode("agent-token"), 0o600);
    running.stop().await;
}

// Fault: a rejected device asks again within seconds and reappears in the
// Hub's pending list, so Reject has no lasting effect.
#[tokio::test]
async fn rejected_pending_enrollment_stops_asking() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().pending = Pending::Reject;
    let dir = TestDir::new("rejected");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    hub.wait_connected(WAIT).await;
    hub.wait_for(WAIT, |e| matches!(e, Event::Closed { .. }).then_some(()))
        .await;
    // rejected_wait is 100 ms in the test timing: ten checks pass here.
    while let Some(event) = hub.next_event(Duration::from_millis(1500)).await {
        assert!(
            !matches!(event, Event::Connected { .. }),
            "a rejected agent connected again"
        );
    }
    running.stop().await;
}

// Fault (canonical_asset_id_matches_hub): the agent keeps a stale asset ID
// after the Hub names the token-bound one, so heartbeats go to no device.
#[tokio::test]
async fn hub_asset_id_header_is_adopted_and_saved() {
    let mut hub = Hub::start(None).await;
    hub.behaviour()
        .accepted_tokens
        .insert("agent-token-3".into());
    hub.behaviour().canonical_asset = Some("nas01-canonical".into());
    let dir = TestDir::new("canonical");
    write(&dir.path("agent-token"), "agent-token-3\n");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["x-asset-id"], "nas01");
    let heartbeat = hub.wait_message("heartbeat", WAIT).await;
    assert_eq!(heartbeat["data"]["asset_id"], "nas01-canonical");
    assert_eq!(heartbeat["data"]["name"], "nas01-canonical");
    let state: Value = serde_json::from_str(&dir.read("enrollment-state.json").unwrap()).unwrap();
    assert_eq!(state["asset_id"], "nas01-canonical");
    running.stop().await;
}
