//! Unit tests that need crate-private access.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use labtether_agent_config::{Environment, HostFacts, Secret, Settings, load};
use labtether_protocol::{MSG_HEARTBEAT, MSG_PONG, Message};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tokio::net::{TcpListener, TcpStream};

use crate::credential::{CommitOutcome, HubIdentity, commit};
use crate::net::HubStream;
use crate::outbox::{Outbox, SendError};
use crate::state::StateFiles;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "lt-core-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn settings_in(dir: &TempDir) -> Settings {
    let path = |name: &str| dir.0.join(name).display().to_string();
    let env = Environment::from_pairs([
        ("LABTETHER_TOKEN_FILE", path("agent-token")),
        ("LABTETHER_AGENT_SETTINGS_FILE", path("agent-config.json")),
        ("LABTETHER_DEVICE_KEY_FILE", path("device-key")),
        ("LABTETHER_DEVICE_PUBLIC_KEY_FILE", path("device-key.pub")),
        (
            "LABTETHER_DEVICE_FINGERPRINT_FILE",
            path("device-fingerprint"),
        ),
    ]);
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    load(&env, &host).unwrap().settings
}

fn identity_with_token(token: &str) -> HubIdentity {
    HubIdentity {
        token: Secret::new(token),
        asset_id: "nas01".into(),
        ws_url: "wss://192.0.2.10:8443/ws/agent".into(),
        api_url: "https://192.0.2.10:8443".into(),
        ..HubIdentity::default()
    }
}

// Invariant failed_commit_rolls_back. Fault: the new token cannot be saved
// but the old token file stays, so a restart presents a stale credential
// (or a half-written state points the old token at the new asset).
#[test]
fn failed_token_commit_removes_the_stale_token_and_writes_no_state() {
    let dir = TempDir::new();
    let mut files = StateFiles::new(&dir.0.join("agent-token"), false);
    fs::write(&files.token, "old-token\n").unwrap();
    files.fail_token_write = true;
    let outcome = commit(&files, &identity_with_token("new-token"), Vec::new());
    assert_eq!(outcome, CommitOutcome::MemoryOnly);
    assert!(!files.token.exists(), "the stale token file is removed");
    assert!(
        !files.state.exists(),
        "no state is written for a token that is not on disk"
    );

    files.fail_token_write = false;
    assert_eq!(
        commit(&files, &identity_with_token("new-token"), Vec::new()),
        CommitOutcome::Saved
    );
    assert_eq!(fs::read_to_string(&files.token).unwrap(), "new-token\n");
}

// Invariant device_key_is_preserved. Fault: an unreadable or damaged key is
// replaced by a new one, which silently changes the device's identity.
#[test]
fn device_key_is_kept_and_never_replaced_when_damaged() {
    let dir = TempDir::new();
    let settings = settings_in(&dir);
    let first = crate::identity::ensure(&settings).unwrap();
    let second = crate::identity::ensure(&settings).unwrap();
    assert_eq!(first.fingerprint, second.fingerprint);

    fs::write(&settings.device_key_file, "not base64 !!\n").unwrap();
    assert!(crate::identity::ensure(&settings).is_err());
    assert_eq!(
        fs::read_to_string(&settings.device_key_file).unwrap(),
        "not base64 !!\n"
    );
}

// Fault: a Hub (or anything answering for it) gets a non-CA certificate saved
// as a trust root through the enrollment answer.
#[test]
fn only_a_ca_certificate_is_accepted_from_enrollment() {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["nas01".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    assert!(crate::tls::is_ca_certificate_pem(&ca.pem()));
    assert!(!crate::tls::is_ca_certificate_pem(&leaf.pem()));
    assert!(!crate::tls::is_ca_certificate_pem("garbage"));
}

// Fault: when the Hub stops reading, queued messages pile up without limit
// (the Go agent had no queue; each sender blocked on one shared lock).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_queue_stays_bounded_when_the_socket_stalls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let socket = tokio_tungstenite::accept_async(tcp).await.unwrap();
        // Hold the socket and never read from it.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(socket);
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let url = format!("ws://{addr}/ws/agent");
    let (socket, _) = tokio_tungstenite::client_async(url, HubStream::Plain(tcp))
        .await
        .unwrap();
    let (sink, _stream) = socket.split();

    let capacity = 8;
    let (outbox, queue) = Outbox::new(capacity, false);
    let write_timeout = Duration::from_millis(300);
    let writer = tokio::spawn(crate::session::writer(
        sink,
        queue,
        Duration::from_secs(60),
        write_timeout,
        std::sync::Arc::default(),
    ));

    let payload = "x".repeat(64 * 1024);
    let message = Message::with_data(MSG_HEARTBEAT, "", &payload).unwrap();
    let (mut accepted, mut full) = (0usize, 0usize);
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_millis(250) {
        match outbox.send(&message) {
            Ok(()) => accepted += 1,
            Err(SendError::Full) => full += 1,
            Err(other) => panic!("unexpected {other:?} before the write timeout"),
        }
        assert!(outbox.queued() <= capacity);
        tokio::task::yield_now().await;
    }
    // Everything accepted fits in the queue plus what the kernel buffers took
    // before the writer blocked; it does not grow with the attempts.
    assert!(full > 10 * accepted, "accepted {accepted}, refused {full}");
    assert!(accepted < capacity + 512, "accepted {accepted}");

    // The blocked write gives up, the writer ends and sends report Closed.
    tokio::time::timeout(Duration::from_secs(3), writer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        outbox.send(&Message::bare(MSG_PONG, "")),
        Err(SendError::Closed)
    );
    hub.abort();
}

// Fault: a socket without a token carries heartbeats or other data before the
// Hub approved it (Go's errEnrollmentPending).
#[test]
fn pending_socket_sends_only_the_enrollment_proof() {
    let (outbox, _queue) = Outbox::new(4, true);
    assert_eq!(
        outbox.send(&Message::bare(MSG_HEARTBEAT, "")),
        Err(SendError::EnrollmentPending)
    );
    let proof = Message::bare(labtether_protocol::MSG_ENROLLMENT_PROOF, "");
    assert_eq!(outbox.send(&proof), Ok(()));
}
