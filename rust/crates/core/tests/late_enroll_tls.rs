//! TLS after an enrollment from the reconnect loop (Go:
//! `enroll_when_reachable_tls_test.go`). Start-up enrollment builds the TLS
//! setup after it saved the Hub's CA, so that CA is trusted from the first
//! connection. Enrollment once the Hub comes back does the same.

mod common;

use std::time::Duration;

use common::pki::TestPki;
use common::setup::{Running, TestDir, fast_timing, settings, start, write};
use common::{Behaviour, EnrollAnswer, Event, Hub, free_address};

const WAIT: Duration = Duration::from_secs(10);

/// Starts the agent with `extra` while no Hub listens, then a Hub with
/// `hub_pki`'s certificate that answers enrollment with `answer_ca`.
/// Returns once the agent connected with the issued token.
async fn enroll_late(
    dir: &TestDir,
    extra: &[(&str, &str)],
    hub_pki: &TestPki,
    answer_ca: Option<&str>,
) -> (Running, Hub) {
    let addr = free_address();
    let mut pairs = vec![("LABTETHER_ENROLLMENT_TOKEN", "enroll-late")];
    pairs.extend_from_slice(extra);
    let settings = settings(dir, &format!("wss://{addr}/ws/agent"), &pairs);
    let running = start(settings, fast_timing()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(dir.read("agent-token").is_none(), "no Hub, no enrollment");

    let mut behaviour = Behaviour {
        ca_pem_in_answer: answer_ca.map(str::to_owned),
        ..Behaviour::default()
    };
    behaviour.enroll.insert(
        "enroll-late".into(),
        EnrollAnswer {
            agent_token: "agent-token-late".into(),
            asset_id: "nas01".into(),
        },
    );
    let mut hub = Hub::start_tls_at(addr, Some(hub_pki.acceptor()), behaviour).await;
    hub.wait_for(WAIT, |e| matches!(e, Event::Enroll { .. }).then_some(()))
        .await;
    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["authorization"], "Bearer agent-token-late");
    (running, hub)
}

/// Puts `next`'s certificate at the Hub's address, closes the agent's
/// socket and reports whether the agent connects again within 3 s. A refusal
/// must be for the certificate.
async fn reconnects_to(hub: &mut Hub, running: &Running, next: &TestPki) -> bool {
    hub.use_certificate(next.acceptor());
    hub.drop_connections();
    while let Some(event) = hub.next_event(Duration::from_secs(3)).await {
        if let Event::Connected { headers, .. } = event {
            assert_eq!(headers["authorization"], "Bearer agent-token-late");
            return true;
        }
    }
    let view = running.agent.status_view().connection;
    assert_eq!(view.last_error_reason, Some("certificate_untrusted"));
    false
}

// Fault: after a late enrollment the agent kept the TLS setup it started
// with. Started with LABTETHER_TLS_SKIP_VERIFY=true and no CA file, it saved
// the CA the Hub returned but went on accepting any certificate until it
// restarted, so a server with another certificate at the Hub's address
// received the agent token.
#[tokio::test]
async fn late_enrollment_trusts_the_saved_hub_ca_from_the_next_connection() {
    let (hub_pki, other) = (TestPki::new(), TestPki::new());
    let dir = TestDir::new("latetls");
    let skip = [("LABTETHER_TLS_SKIP_VERIFY", "true")];
    let (running, mut hub) =
        enroll_late(&dir, &skip, &hub_pki, Some(hub_pki.ca_pem.as_str())).await;
    assert_eq!(dir.read("ca.crt").as_deref(), Some(hub_pki.ca_pem.as_str()));
    assert!(!reconnects_to(&mut hub, &running, &other).await);
    assert!(reconnects_to(&mut hub, &running, &hub_pki).await);
    running.stop().await;
}

// Fault: a late enrollment turns certificate checks on without a CA from
// the Hub, so an agent on skip-verify loses a Hub with a self-signed
// certificate. As at start, skip-verify stays.
#[tokio::test]
async fn late_enrollment_without_a_ca_keeps_skip_verify() {
    let (hub_pki, other) = (TestPki::new(), TestPki::new());
    let dir = TestDir::new("latenoca");
    let skip = [("LABTETHER_TLS_SKIP_VERIFY", "true")];
    let (running, mut hub) = enroll_late(&dir, &skip, &hub_pki, None).await;
    assert!(dir.read("ca.crt").is_none());
    assert!(reconnects_to(&mut hub, &running, &other).await);
    running.stop().await;
}

// Fault: a late enrollment trusts the Hub's CA over a CA file the person set
// (for a TLS proxy in front of the Hub), so the agent loses the proxy.
#[tokio::test]
async fn late_enrollment_keeps_a_ca_file_the_person_set() {
    let (proxy, hub_internal) = (TestPki::new(), TestPki::new());
    let dir = TestDir::new("lateproxy");
    write(&dir.path("proxy-ca.pem"), &proxy.ca_pem);
    let ca = dir.path("proxy-ca.pem").display().to_string();
    let extra = [
        ("LABTETHER_TLS_SKIP_VERIFY", "true"),
        ("LABTETHER_TLS_CA_FILE", ca.as_str()),
    ];
    let (running, mut hub) =
        enroll_late(&dir, &extra, &proxy, Some(hub_internal.ca_pem.as_str())).await;
    assert!(dir.read("ca.crt").is_none());
    assert!(!reconnects_to(&mut hub, &running, &hub_internal).await);
    assert!(reconnects_to(&mut hub, &running, &proxy).await);
    running.stop().await;
}

// Fault: with LABTETHER_TLS_CA_ONLY on, the CA in a late enrollment answer
// replaces the pinned CA, so whoever answers enrollment chooses what the
// agent trusts.
#[tokio::test]
async fn late_enrollment_never_replaces_a_pinned_ca() {
    let (hub_pki, other) = (TestPki::new(), TestPki::new());
    let dir = TestDir::new("latecaonly");
    write(&dir.path("ca.crt"), &hub_pki.ca_pem);
    let ca = dir.path("ca.crt").display().to_string();
    let extra = [
        ("LABTETHER_TLS_CA_ONLY", "true"),
        ("LABTETHER_TLS_CA_FILE", ca.as_str()),
    ];
    let (running, mut hub) = enroll_late(&dir, &extra, &hub_pki, Some(other.ca_pem.as_str())).await;
    assert_eq!(dir.read("ca.crt").as_deref(), Some(hub_pki.ca_pem.as_str()));
    assert!(!reconnects_to(&mut hub, &running, &other).await);
    assert!(reconnects_to(&mut hub, &running, &hub_pki).await);
    running.stop().await;
}
