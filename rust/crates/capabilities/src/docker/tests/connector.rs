//! What the page starts and what each heartbeat lists, as Go's `run.go`
//! and `connector_discovery.go`.

use labtether_agent_config::{Environment, HostFacts, Settings, load};
use labtether_agent_core::Features;

use super::engine::{Reply, StandIn};
use crate::docker::{CONNECTOR, DISCOVERY, EVENTS, STATS, metadata_endpoint, register};

fn settings(pairs: &[(&str, &str)]) -> Settings {
    let dir = std::env::temp_dir().join("lt-docker-unused");
    let path = |name: &str| dir.join(name).display().to_string();
    let mut all = vec![
        ("LABTETHER_TOKEN_FILE".to_owned(), path("agent-token")),
        (
            "LABTETHER_AGENT_SETTINGS_FILE".to_owned(),
            path("agent-config.json"),
        ),
    ];
    all.extend(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    load(&Environment::from_pairs(all), &host).unwrap().settings
}

/// The producers, the heartbeat's connectors as `(endpoint, reachable)`,
/// the handlers and the advertisement of a build with only this page.
fn built(pairs: &[(&str, &str)]) -> (Vec<&'static str>, Vec<(String, bool)>, Features) {
    let mut features = Features::new();
    register(&mut features, &settings(pairs));
    let connectors = features
        .connector_sources()
        .iter()
        .flat_map(|list| list())
        .map(|info| {
            assert_eq!(info.r#type, "docker");
            (info.endpoint, info.reachable)
        })
        .collect();
    (features.producer_names(), connectors, features)
}

// Faults: the heartbeat leaves out an endpoint that answers (the Hub never
// sets up its Docker collector, so the Containers page stays empty), lists
// one that does not in `auto` mode, or leaves it out in `true` mode; the
// collector starts on an endpoint that did not answer at start, or not on
// one that did; Docker runs when turned off; the page registers a handler
// or advertises a word (`cap_docker=manage` would make the Hub send
// container and Compose actions this agent drops).
#[test]
fn starts_and_lists_what_go_does() {
    let answering = StandIn::start("ping", vec![("/_ping".into(), Reply::ok("OK"))]);
    let live = answering.socket.display().to_string();
    let collector = vec![CONNECTOR, DISCOVERY, STATS, EVENTS];
    let missing = "/nonexistent/docker.sock";

    let (producers, connectors, features) = built(&[("LABTETHER_DOCKER_SOCKET", &live)]);
    assert_eq!(producers, collector);
    assert_eq!(connectors, [(format!("unix://{live}"), true)]);
    assert!(features.message_types().is_empty());
    let metadata = features.advertised().metadata;
    assert!(
        metadata.keys().all(|key| key == "agent_capability_mode"),
        "{metadata:?}"
    );

    let unix_form = format!("unix://{live}");
    let (producers, connectors, _) = built(&[
        ("LABTETHER_DOCKER_SOCKET", &unix_form),
        ("LABTETHER_DOCKER_ENABLED", "TRUE"),
    ]);
    assert_eq!(
        (producers, connectors),
        (collector.clone(), vec![(unix_form.clone(), true)])
    );

    let (producers, connectors, _) = built(&[("LABTETHER_DOCKER_SOCKET", missing)]);
    assert_eq!((producers, connectors), (vec![CONNECTOR], vec![]));

    let (producers, connectors, _) = built(&[
        ("LABTETHER_DOCKER_SOCKET", missing),
        ("LABTETHER_DOCKER_ENABLED", "true"),
    ]);
    assert_eq!(
        (producers, connectors),
        (vec![CONNECTOR], vec![(format!("unix://{missing}"), false)])
    );

    let tcp = "http://192.0.2.10:2375";
    let (producers, connectors, _) = built(&[
        ("LABTETHER_DOCKER_SOCKET", tcp),
        ("LABTETHER_DOCKER_ENABLED", "true"),
    ]);
    assert_eq!(
        (producers, connectors),
        (vec![CONNECTOR], vec![(tcp.to_owned(), false)])
    );

    let (producers, connectors, _) = built(&[
        ("LABTETHER_DOCKER_SOCKET", &live),
        ("LABTETHER_DOCKER_ENABLED", "false"),
    ]);
    assert!(producers.is_empty() && connectors.is_empty());
}

// Fault: the endpoint reaches the Hub in another form than Go's
// (`unix://` before an absolute path), so the Hub sees a different
// endpoint for the same Docker.
#[test]
fn endpoints_are_listed_in_go_form() {
    assert_eq!(
        metadata_endpoint("/var/run/docker.sock"),
        "unix:///var/run/docker.sock"
    );
    assert_eq!(
        metadata_endpoint("unix:///run/user/1000/docker.sock"),
        "unix:///run/user/1000/docker.sock"
    );
    assert_eq!(
        metadata_endpoint(" http://192.0.2.10:2375 "),
        "http://192.0.2.10:2375"
    );
}
