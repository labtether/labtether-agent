//! What happens to a one-use token whose enrollment at start failed, as in
//! the Go agent. When the Hub did not answer, the reconnect loop enrolls with
//! the token before it would connect without one (Go:
//! `enroll_when_reachable.go`). When the Hub refused it, the agent connects as
//! a pending device; `run.go` keeps the token armed for re-enrollment, and
//! `reconnectLoop` uses it at the third refused connect in a row, then at most
//! once per re-enrollment spacing. A current Hub refuses a socket without a
//! token (403) only for a device an admin rejected.

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

/// A Hub that holds a socket without a token as a pending device and accepts
/// `token` once.
fn accepting_hub(token: &str) -> Behaviour {
    let mut behaviour = Behaviour::default();
    behaviour.enroll.insert(
        token.into(),
        EnrollAnswer {
            agent_token: "agent-token-late".into(),
            asset_id: "nas01".into(),
        },
    );
    behaviour
}

// Fault: an agent started while its Hub was down connected without its token
// once the Hub came back, so the Hub held it as a pending device for an admin
// to approve and the one-use token was never used (the Go agent did the
// same). A 503 (a Hub down behind a proxy) still means "not there", not a
// refusal. After the late enrollment the token file is gone, which the Mac
// and Windows apps watch for, and a restart uses the saved token without
// enrolling again.
#[tokio::test]
async fn staged_token_enrolls_when_the_hub_comes_back() {
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
    let view = running.agent.status_view().connection;
    assert_eq!(
        (
            view.state.as_str(),
            view.last_error.as_deref(),
            view.last_error_reason
        ),
        ("connecting", Some("transient"), Some("connection_refused"))
    );

    let behaviour = Behaviour {
        enroll_unavailable: 2,
        ..accepting_hub("enroll-late")
    };
    let mut hub = Hub::start_at(addr, behaviour).await;
    let mut unavailable = 0;
    let body = hub
        .wait_for(WAIT, |e| match e {
            Event::Enroll { .. } if unavailable < 2 => {
                unavailable += 1;
                None
            }
            Event::Enroll { body } => Some(body.clone()),
            Event::Connected { .. } | Event::Refused { .. } => {
                panic!("the agent connected without its token")
            }
            _ => None,
        })
        .await;
    assert_eq!(body["enrollment_token"], "enroll-late");
    assert_eq!(body["device_proof_version"], "v1");
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

const USED: &str = "This enrollment token was already used. Make a new one in Devices, Add device.";

// Fault: a token the Hub refuses once it is back (used, expired, revoked:
// all 401) is offered again on every reconnect, or the agent stops. As when
// the Hub refuses it at start, the agent asks once, then connects as a
// pending device, shows the Hub's words and keeps the token file.
#[tokio::test]
async fn refused_token_when_the_hub_comes_back_falls_back_to_pending_once() {
    let addr = free_address();
    let dir = TestDir::new("usedlate");
    let token_file = dir.path("enroll.token");
    write(&token_file, "enroll-used\n");
    let token_path = token_file.display().to_string();
    let settings = settings(
        &dir,
        &format!("ws://{addr}/ws/agent"),
        &[("LABTETHER_ENROLLMENT_TOKEN_FILE", &token_path)],
    );
    let running = start(settings, fast_timing()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The Hub closes each pending socket at once, so the agent reconnects.
    let behaviour = Behaviour {
        enroll_refusal: USED.into(),
        close_at_once: true,
        ..Behaviour::default()
    };
    let mut hub = Hub::start_at(addr, behaviour).await;
    let mut enrolls = 0;
    for _ in 0..3 {
        let headers = hub
            .wait_for(WAIT, |e| match e {
                Event::Enroll { body } => {
                    assert_eq!(body["enrollment_token"], "enroll-used");
                    enrolls += 1;
                    None
                }
                Event::Connected { headers, .. } => Some(headers.clone()),
                Event::Refused { .. } => panic!("the Hub refused a socket"),
                _ => None,
            })
            .await;
        assert_eq!(headers["x-request-enrollment"], "true");
        assert!(!headers.contains_key("authorization"));
    }
    assert_eq!(enrolls, 1, "the refused token is offered once");
    let view = running.agent.status_view().connection;
    assert_eq!(view.state.as_str(), "auth_failed");
    assert_eq!(
        view.last_error.as_deref(),
        Some("enrollment_token_rejected")
    );
    assert_eq!(view.enrollment_error.as_deref(), Some(USED));
    assert!(token_file.exists(), "a refused token file stays");
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
