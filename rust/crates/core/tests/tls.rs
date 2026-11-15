//! TLS trust rules, ported from Go's `tls.go` and `tls_ca_only.go`, and the
//! trust cases in the protocol's `connection-enrollment-v1.json`:
//!
//! - `system-trust` (no CA, no skip): accepted as a setting; a private Hub CA
//!   is then not trusted.
//! - `custom-ca`: the Hub signed by the configured CA is trusted.
//! - `reject-custom-ca-and-skip-conflict`: CA and skip together are not
//!   accepted as "skip"; the CA wins and verification stays on (Go logs
//!   "configured TLS CA takes priority").

mod common;

use std::time::Duration;

use common::pki::TestPki;
use common::setup::{TestDir, fast_timing, settings, start, write};
use common::{EnrollAnswer, Event, Hub};
use labtether_agent_core::StartError;
use labtether_agent_core::tls::TlsError;

async fn tls_hub(pki: &TestPki) -> Hub {
    let hub = Hub::start(Some(pki.acceptor())).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    hub
}

fn dir_with_token(name: &str) -> TestDir {
    let dir = TestDir::new(name);
    write(&dir.path("agent-token"), "agent-token");
    dir
}

/// True when the agent opens a socket within 1.5 s.
async fn connects(hub: &mut Hub) -> bool {
    while let Some(event) = hub.next_event(Duration::from_millis(1500)).await {
        if matches!(event, Event::Connected { .. }) {
            return true;
        }
    }
    false
}

// Fault: the configured Hub CA is not trusted, so the agent cannot connect.
#[tokio::test]
async fn custom_ca_is_trusted() {
    let pki = TestPki::new();
    let mut hub = tls_hub(&pki).await;
    let dir = dir_with_token("ca");
    write(&dir.path("hub-ca.pem"), &pki.ca_pem);
    let ca = dir.path("hub-ca.pem").display().to_string();
    let running = start(
        settings(&dir, &hub.ws_url(), &[("LABTETHER_TLS_CA_FILE", &ca)]),
        fast_timing(),
    )
    .await
    .unwrap();
    assert!(connects(&mut hub).await);
    running.stop().await;
}

// Fault (reject-custom-ca-and-skip-conflict): a stale skip-verify setting
// turns verification off although a CA is configured, so any server holding
// any certificate receives the agent token.
#[tokio::test]
async fn ca_with_skip_verify_still_verifies() {
    let pki = TestPki::new();
    let other = TestPki::new();
    let mut hub = tls_hub(&pki).await;
    let dir = dir_with_token("conflict");
    write(&dir.path("other-ca.pem"), &other.ca_pem);
    let ca = dir.path("other-ca.pem").display().to_string();
    let extra = [
        ("LABTETHER_TLS_CA_FILE", ca.as_str()),
        ("LABTETHER_TLS_SKIP_VERIFY", "true"),
    ];
    let running = start(settings(&dir, &hub.ws_url(), &extra), fast_timing())
        .await
        .unwrap();
    assert!(
        !connects(&mut hub).await,
        "a Hub signed by another CA is refused"
    );
    running.stop().await;
}

// Fault: a private Hub CA is trusted without being configured (system-trust
// case), or opt-in skip-verify (bootstrap) does not work at all.
#[tokio::test]
async fn system_roots_refuse_a_private_ca_and_skip_verify_is_opt_in() {
    let pki = TestPki::new();
    let mut hub = tls_hub(&pki).await;
    let dir = dir_with_token("system");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    assert!(!connects(&mut hub).await);
    running.stop().await;

    let running = start(
        settings(
            &dir,
            &hub.ws_url(),
            &[("LABTETHER_TLS_SKIP_VERIFY", "true")],
        ),
        fast_timing(),
    )
    .await
    .unwrap();
    assert!(connects(&mut hub).await);
    running.stop().await;
}

// Fault: with LABTETHER_TLS_CA_ONLY on and no usable CA file, the agent
// starts anyway and falls back to the system roots.
#[tokio::test]
async fn ca_only_without_a_usable_file_stops_start() {
    let dir = dir_with_token("caonly");
    let url = "wss://127.0.0.1:9/ws/agent";
    let result = start(
        settings(&dir, url, &[("LABTETHER_TLS_CA_ONLY", "true")]),
        fast_timing(),
    )
    .await;
    assert!(matches!(
        result,
        Err(StartError::Tls(TlsError::CaOnlyWithoutFile))
    ));

    write(&dir.path("empty.pem"), "not a certificate");
    let empty = dir.path("empty.pem").display().to_string();
    let extra = [
        ("LABTETHER_TLS_CA_ONLY", "true"),
        ("LABTETHER_TLS_CA_FILE", empty.as_str()),
    ];
    let result = start(settings(&dir, url, &extra), fast_timing()).await;
    assert!(matches!(
        result,
        Err(StartError::Tls(TlsError::CaOnlyEmpty(_)))
    ));
}

// Fault: the CA the Hub returns at enrollment is not saved or not used, so
// the agent stays on skip-verify (or cannot reconnect) after bootstrap.
#[tokio::test]
async fn enrollment_saves_the_hub_ca_and_verification_turns_on() {
    let pki = TestPki::new();
    let mut hub = Hub::start(Some(pki.acceptor())).await;
    hub.behaviour().enroll.insert(
        "enroll-ca".into(),
        EnrollAnswer {
            agent_token: "agent-token-ca".into(),
            asset_id: "nas01".into(),
        },
    );
    hub.behaviour().ca_pem_in_answer = Some(pki.ca_pem.clone());
    let dir = TestDir::new("saveca");
    let extra = [
        ("LABTETHER_TLS_SKIP_VERIFY", "true"),
        ("LABTETHER_ENROLLMENT_TOKEN", "enroll-ca"),
    ];
    let running = start(settings(&dir, &hub.ws_url(), &extra), fast_timing())
        .await
        .unwrap();
    assert!(connects(&mut hub).await);
    assert_eq!(dir.read("ca.crt").as_deref(), Some(pki.ca_pem.as_str()));
    assert_eq!(dir.mode("ca.crt"), 0o644);
    running.stop().await;

    // On restart the saved CA overrides skip-verify: a Hub with another CA
    // at the same address is refused.
    let other = TestPki::new();
    let mut impostor = Hub::start(Some(other.acceptor())).await;
    impostor
        .behaviour()
        .accepted_tokens
        .insert("agent-token-ca".into());
    let extra = [("LABTETHER_TLS_SKIP_VERIFY", "true")];
    let running = start(settings(&dir, &impostor.ws_url(), &extra), fast_timing())
        .await
        .unwrap();
    assert!(!connects(&mut impostor).await);
    running.stop().await;
}
