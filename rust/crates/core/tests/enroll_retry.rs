//! What happens to a one-use token whose enrollment at start failed, as in
//! the Go agent: `run.go` arms re-enrollment whenever the token is still set
//! after start, and `reconnectLoop` uses it at the third refused connect in a
//! row, then at most once per re-enrollment spacing. A current Hub holds a
//! socket without a token as a pending enrollment; it refuses one (403) only
//! for a device an admin rejected, and that is when the token is used.

mod common;

use std::time::Duration;

use common::setup::{TestDir, fast_timing, settings, start, write};
use common::{Behaviour, EnrollAnswer, Event, Hub, free_address};
use labtether_agent_core::Timing;

const WAIT: Duration = Duration::from_secs(10);

/// A Hub that refuses sockets without a token and accepts `token` once.
fn refusing_hub(token: &str) -> Behaviour {
    let mut behaviour = Behaviour {
        refuse_pending: true,
        ..Behaviour::default()
    };
    if !token.is_empty() {
        behaviour.enroll.insert(
            token.into(),
            EnrollAnswer {
                agent_token: "agent-token-late".into(),
                asset_id: "nas01".into(),
            },
        );
    }
    behaviour
}

// Fault: the agent dropped the one-use token when the first enrollment found
// no Hub, so once the Hub answered it was refused three times, waited, and
// had nothing to enroll with: it never enrolled until restarted. Go keeps
// the token and re-enrolls at the third refusal. After that the token file
// is gone and a restart uses the issued token without enrolling again.
#[tokio::test]
async fn first_enrollment_without_a_hub_re_enrolls_at_the_third_refusal() {
    let addr = free_address();
    let dir = TestDir::new("nohub");
    let token_file = dir.path("enroll.token");
    write(&token_file, "enroll-late\n");
    let token_path = token_file.display().to_string();
    let settings = settings(
        &dir,
        &format!("ws://{addr}/ws/agent"),
        &[("LABTETHER_ENROLLMENT_TOKEN_FILE", &token_path)],
    );
    let running = start(settings.clone(), fast_timing()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        token_file.exists(),
        "a failed enrollment keeps the one-use token file"
    );
    assert!(dir.read("agent-token").is_none());

    let mut hub = Hub::start_at(addr, refusing_hub("enroll-late")).await;
    let mut refused = 0;
    let body = hub
        .wait_for(WAIT, |e| match e {
            Event::Refused { status, headers } => {
                assert_eq!(*status, 403);
                assert_eq!(headers["x-request-enrollment"], "true");
                assert!(!headers.contains_key("authorization"));
                refused += 1;
                None
            }
            Event::Enroll { body } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(refused, 3, "re-enrollment starts at the third refusal");
    assert_eq!(body["enrollment_token"], "enroll-late");
    assert_eq!(body["device_proof_version"], "v2");
    assert_eq!(body["hostname"], "nas01");
    let headers = hub.wait_connected(WAIT).await;
    assert_eq!(headers["authorization"], "Bearer agent-token-late");
    assert_eq!(
        dir.read("agent-token").as_deref(),
        Some("agent-token-late\n")
    );
    assert!(!token_file.exists(), "the used token file is removed");
    running.stop().await;

    let running = start(settings, fast_timing()).await.unwrap();
    let headers = hub
        .wait_for(WAIT, |e| match e {
            Event::Enroll { .. } => panic!("a restart must not enroll again"),
            Event::Connected { headers, .. } => Some(headers.clone()),
            _ => None,
        })
        .await;
    assert_eq!(headers["authorization"], "Bearer agent-token-late");
    running.stop().await;
}

// Faults: a token the Hub refused at start is dropped, so Go's second try at
// the third refused connect never happens; or it is tried in a loop. Go
// tries it again only at the end of a long wait, and only when the last try
// is older than the spacing: with Go's 5-minute wait and 10-minute spacing,
// at every second long wait. The same ratio is used here, scaled down.
#[tokio::test]
async fn refused_token_is_tried_at_the_third_refusal_then_once_per_spacing() {
    let addr = free_address();
    let mut hub = Hub::start_at(addr, refusing_hub("")).await;
    let dir = TestDir::new("spent");
    let settings = settings(
        &dir,
        &format!("ws://{addr}/ws/agent"),
        &[("LABTETHER_ENROLLMENT_TOKEN", "spent-token")],
    );
    let timing = Timing {
        auth_backoff: Duration::from_secs(1),
        re_enroll_spacing: Duration::from_millis(1500),
        ..fast_timing()
    };
    let running = start(settings, timing).await.unwrap();
    // E: an enrollment request, R: a refused connect.
    let mut seen = String::new();
    while seen.matches('R').count() < 8 {
        let mark = hub
            .wait_for(WAIT, |e| match e {
                Event::Enroll { body } => {
                    assert_eq!(body["enrollment_token"], "spent-token");
                    Some('E')
                }
                Event::Refused { .. } => Some('R'),
                _ => None,
            })
            .await;
        seen.push(mark);
    }
    running.stop().await;
    assert_eq!(seen, "ERRRERRERRER");
}
