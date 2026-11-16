//! The local server's HTTP behaviour against Go's: the bearer check and
//! which pages it covers, the pages' status codes, types and bodies,
//! `If-None-Match` round trips, Go's mux answers, the API off for a remote
//! bind without a token, the bind retry, and the limits Go does not have.

mod support;

use std::sync::Arc;
use std::time::Duration;

use labtether_agent_config::{LocalApiSettings, LocalAuth, Secret};
use labtether_agent_core::status::StatusView;
use labtether_agent_local_api::{Limits, Source, run_with};
use serde_json::Value;
use support::{exchange, fixture, free_port, get, view_from_fixture};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

const SECRET: &str = "local-api-test-secret";

struct Fixed(StatusView);

impl Source for Fixed {
    fn status_view(&self) -> StatusView {
        self.0.clone()
    }
}

fn settings(port: u16, auth: LocalAuth) -> LocalApiSettings {
    LocalApiSettings {
        port: port.to_string(),
        bind_address: "127.0.0.1".into(),
        auth,
        app_version: "dev".into(),
    }
}

fn token() -> LocalAuth {
    LocalAuth::Token(Secret::new(SECRET).unwrap())
}

fn quick() -> Limits {
    Limits {
        retry_first: Duration::from_millis(200),
        retry_max: Duration::from_millis(400),
        max_connections: 2,
        header_timeout: Duration::from_millis(500),
        max_header_bytes: 8 * 1024,
        max_age: Duration::from_secs(2),
        close_grace: Duration::from_millis(500),
    }
}

/// Starts the API with the `connected` fixture's view.
async fn serve(port: u16, auth: LocalAuth, limits: Limits) -> watch::Sender<bool> {
    let (_, value) = fixture("connected");
    let source: Arc<dyn Source> = Arc::new(Fixed(view_from_fixture(&value).0));
    let (stop, receiver) = watch::channel(false);
    let settings = settings(port, auth);
    tokio::spawn(
        async move { run_with("labtether-agent", &settings, source, limits, receiver).await },
    );
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return stop;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the local API did not start");
}

// Faults: a page answers without the token, or with a wrong one; the
// probes need a token (the apps' health checks fail); Go's error bodies
// change (the Mac app reads 401 as auth_failed); an unknown path reveals
// 404 before the token check.
#[tokio::test]
async fn bearer_check_follows_go() {
    let port = free_port();
    let _stop = serve(port, token(), Limits::default()).await;
    let good = format!("Bearer {SECRET}");
    let missing = "{\"error\":\"missing bearer token\"}\n";
    let invalid = "{\"error\":\"invalid bearer token\"}\n";
    for path in [
        "/agent/status",
        "/agent/info",
        "/agent/telemetry",
        "/metrics",
        "/nope",
    ] {
        for (header, body) in [
            (None, missing),
            (Some("bearer local-api-test-secret"), missing),
            (Some("Bearer wrong"), invalid),
            (Some("Bearer local-api-test-secre"), invalid),
        ] {
            let headers: Vec<(&str, &str)> =
                header.map(|h| ("Authorization", h)).into_iter().collect();
            let answer = get(port, path, &headers).await.unwrap();
            assert_eq!(
                (answer.status, answer.body.as_str()),
                (401, body),
                "{path} {header:?}"
            );
            assert_eq!(answer.headers["content-type"], "application/json");
        }
    }
    for path in ["/healthz", "/readyz", "/version"] {
        assert_eq!(get(port, path, &[]).await.unwrap().status, 200, "{path}");
    }
    let padded = format!("  {good}  ");
    for header in [good.as_str(), padded.as_str()] {
        let answer = get(port, "/agent/info", &[("Authorization", header)])
            .await
            .unwrap();
        assert_eq!(answer.status, 200);
    }
    let answer = get(port, "/nope", &[("Authorization", &good)])
        .await
        .unwrap();
    assert_eq!(
        (answer.status, answer.body.as_str()),
        (404, "404 page not found\n")
    );
    assert_eq!(answer.headers["content-type"], "text/plain; charset=utf-8");
}

// Faults: a page's body, type or map key order differs from Go's.
#[tokio::test]
async fn pages_follow_go() {
    let port = free_port();
    let _stop = serve(port, LocalAuth::Open { remote: false }, Limits::default()).await;
    let healthz: Value =
        serde_json::from_str(&get(port, "/healthz", &[]).await.unwrap().body).unwrap();
    assert_eq!(healthz["status"], "ok");
    assert_eq!(
        healthz.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["service", "status", "timestamp"]
    );
    let readyz = get(port, "/readyz", &[]).await.unwrap();
    assert_eq!(
        readyz.body,
        "{\"ready\":true,\"service\":\"labtether-agent\"}\n"
    );
    let version: Value =
        serde_json::from_str(&get(port, "/version", &[]).await.unwrap().body).unwrap();
    assert_eq!(version["version"], "dev");
    let info = get(port, "/agent/info", &[]).await.unwrap();
    assert_eq!(
        info.body,
        "{\"os\":\"linux\",\"mode\":\"interactive-terminal-first\",\"status\":\"active\"}\n"
    );
    let telemetry = get(port, "/agent/telemetry", &[]).await.unwrap();
    let (_, connected) = fixture("connected");
    assert_eq!(
        serde_json::from_str::<Value>(&telemetry.body).unwrap(),
        connected["metrics"]
    );
    let metrics = get(port, "/metrics", &[]).await.unwrap();
    assert_eq!(
        metrics.headers["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert!(metrics.body.starts_with(
        "# HELP labtether_agent_cpu_usage_percent CPU usage percentage.\n# TYPE labtether_agent_cpu_usage_percent gauge\nlabtether_agent_cpu_usage_percent{asset_id=\"nas01\"} 12.5000\n"
    ));
    assert!(
        metrics
            .body
            .contains("labtether_agent_network_rx_bytes_total{asset_id=\"nas01\"} 48213377024\n")
    );
    assert!(
        metrics
            .body
            .ends_with("labtether_agent_scrape_timestamp_seconds{asset_id=\"nas01\"} 1794649262\n")
    );
    let moved = get(port, "/agent//status?x=1", &[]).await.unwrap();
    assert_eq!(
        (moved.status, moved.headers["location"].as_str()),
        (307, "/agent/status?x=1")
    );
    let no_host = exchange(port, "GET /healthz HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(no_host.status, 400);
}

// Faults: the apps' conditional polls never get 304 (`*`, a weak tag, a
// list), or a 304 carries a body or loses the ETag.
#[tokio::test]
async fn if_none_match_round_trips() {
    let port = free_port();
    let _stop = serve(port, LocalAuth::Open { remote: false }, Limits::default()).await;
    let first = get(port, "/agent/status", &[]).await.unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.headers["content-type"], "application/json");
    let tag = first.headers["etag"].clone();
    let weak = format!("W/{tag}");
    let list = format!("\"other\", {tag}");
    for header in [tag.as_str(), weak.as_str(), "*", list.as_str()] {
        let again = get(port, "/agent/status", &[("If-None-Match", header)])
            .await
            .unwrap();
        assert_eq!((again.status, again.body.as_str()), (304, ""), "{header}");
        assert_eq!(again.headers["etag"], tag);
    }
    let stale = get(port, "/agent/status", &[("If-None-Match", "\"stale\"")])
        .await
        .unwrap();
    assert_eq!((stale.status, stale.body), (200, first.body));
}

// Fault: a non-loopback bind without a token serves the agent's state to
// the network (Go turns the API off).
#[tokio::test]
async fn remote_bind_without_token_stays_off() {
    let port = free_port();
    let (_stop, receiver) = watch::channel(false);
    let mut settings = settings(port, LocalAuth::Off("non-loopback".into()));
    settings.bind_address = "0.0.0.0".into();
    let (_, value) = fixture("connected");
    let source: Arc<dyn Source> = Arc::new(Fixed(view_from_fixture(&value).0));
    let run = run_with("labtether-agent", &settings, source, quick(), receiver);
    tokio::time::timeout(Duration::from_secs(1), run)
        .await
        .expect("returns at once");
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

// Fault: a port held by another program at start stops the API for good
// (Go retries) or stops the agent.
#[tokio::test]
async fn busy_port_is_retried() {
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    let (_stop, receiver) = watch::channel(false);
    let (_, value) = fixture("connected");
    let source: Arc<dyn Source> = Arc::new(Fixed(view_from_fixture(&value).0));
    let settings = settings(port, LocalAuth::Open { remote: false });
    tokio::spawn(
        async move { run_with("labtether-agent", &settings, source, quick(), receiver).await },
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(holder);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(answer) = get(port, "/healthz", &[]).await
            && answer.status == 200
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the API did not bind after the port was freed");
}

// Faults: a local program holds the API with slow or huge headers or many
// idle connections, so the app's poll gets no answer.
#[tokio::test]
async fn limits_keep_the_api_answering() {
    let port = free_port();
    let _stop = serve(port, LocalAuth::Open { remote: false }, quick()).await;
    let huge = format!(
        "GET /healthz HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(16 * 1024)
    );
    assert_eq!(exchange(port, &huge).await.unwrap().status, 431);
    // A request that never finishes its headers is closed.
    let mut slow = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    slow.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        let mut buf = [0u8; 512];
        loop {
            match tokio::io::AsyncReadExt::read(&mut slow, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "a slow header is cut off");
    // Two idle connections fill the slots; a third is closed at once; the
    // slots come back when those two reach their age limit.
    let _idle1 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _idle2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refused = get(port, "/healthz", &[]).await;
    assert!(
        refused.map(|a| a.status).unwrap_or(0) != 200,
        "a third connection is refused"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(get(port, "/healthz", &[]).await.unwrap().status, 200);
}
