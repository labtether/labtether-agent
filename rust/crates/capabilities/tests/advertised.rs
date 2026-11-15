//! What the heartbeat advertises must match the handlers registered: a page
//! cannot be advertised without its handler, and a page the Hub gates on an
//! advertisement cannot have a handler the Hub never uses.
//!
//! The table says which request each advertised value makes the Hub or the
//! console send. It follows the Hub's `InferCapabilityIDsFromAssetMetadata`
//! (`internal/hubapi/resources/canonical_helpers.go`), the console's
//! `useNodeCapabilities.ts`, and the Go agent's `capabilities` list
//! (`internal/agentcore/run.go`). A value missing from the table fails the
//! test, so a new advertisement needs a row here.

use std::collections::BTreeSet;

use labtether_agent_capabilities::all;
use labtether_agent_config::{Environment, HostFacts, load};

/// `(metadata key, value, request it makes the Hub send)`.
const CAP_VALUES: &[(&str, &str, &str)] = &[
    ("cap_network", "list", "network.list"),
    ("cap_network", "action", "network.action"),
    ("cap_services", "list", "service.list"),
    ("cap_services", "action", "service.action"),
    ("cap_packages", "list", "package.list"),
    ("cap_packages", "action", "package.action"),
    ("cap_schedules", "list", "cron.list"),
    ("cap_logs", "query", "journal.query"),
];

/// `(heartbeat capability, request it makes the Hub send)`.
const CAPABILITIES: &[(&str, &str)] = &[
    ("terminal", "terminal.start"),
    ("desktop", "desktop.start"),
    ("files", "file.list"),
    ("power", "power.action"),
    ("webrtc", "webrtc.start"),
];

/// Backend keys and the values allowed for them: Go's names. An action
/// backend other than `none` needs the matching `action` value.
const BACKENDS: &[(&str, &[&str])] = &[
    ("network_backend", &["ifconfig"]),
    ("network_action_backend", &["none"]),
];

fn features() -> labtether_agent_core::Features {
    let dir = std::env::temp_dir().join("lt-capabilities-unused");
    let path = |name: &str| dir.join(name).display().to_string();
    let env = Environment::from_pairs([
        ("LABTETHER_TOKEN_FILE", path("agent-token")),
        ("LABTETHER_AGENT_SETTINGS_FILE", path("agent-config.json")),
    ]);
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    all(&load(&env, &host).unwrap().settings)
}

// Faults: a page advertised without its handler (the Hub offers a page
// that times out), a handled page the Hub gates on an advertisement left
// unadvertised (the console falls back to its defaults and offers network
// controls this agent lacks), an advertisement in a form Go never sends,
// or a heartbeat capability (terminal, files, ...) this agent cannot serve.
#[test]
fn advertisements_match_handlers() {
    let features = features();
    let handled: BTreeSet<&str> = features.message_types().into_iter().collect();
    let advertised = features.advertised();

    let mut implied = BTreeSet::new();
    for (key, value) in &advertised.metadata {
        if let Some((_, allowed)) = BACKENDS.iter().find(|(name, _)| name == key) {
            assert!(
                allowed.contains(&value.as_str()),
                "{key}={value} is not a value this agent may send"
            );
            continue;
        }
        assert!(key.starts_with("cap_"), "unknown advertised key {key}");
        for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let row = CAP_VALUES.iter().find(|(k, v, _)| k == key && *v == token);
            let (_, _, request) =
                row.unwrap_or_else(|| panic!("{key}={token} has no row in CAP_VALUES"));
            implied.insert(*request);
        }
    }
    for name in &advertised.capabilities {
        let row = CAPABILITIES.iter().find(|(n, _)| n == name);
        implied.insert(
            row.unwrap_or_else(|| panic!("capability {name} has no row"))
                .1,
        );
    }
    for request in &implied {
        assert!(
            handled.contains(request),
            "advertised {request} has no handler"
        );
    }
    for (key, value, request) in CAP_VALUES {
        if handled.contains(request) {
            assert!(
                implied.contains(request),
                "{request} is handled but {key} does not say {value}"
            );
        }
    }
    for (name, request) in CAPABILITIES {
        if handled.contains(request) {
            assert!(
                implied.contains(request),
                "{request} is handled but capability {name} is not advertised"
            );
        }
    }
}
