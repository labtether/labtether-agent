//! The macOS build is the monitoring edition the Mac App Store app bundles.
//! It runs in the App Sandbox, so it may build in only the pages that work
//! there and must advertise nothing else.
//!
//! Risk: a page that needs an outside program or `/proc` (the process list,
//! services, packages, logs, terminal) is registered or advertised on macOS,
//! so the Hub offers it and the request fails or times out in the sandbox.

#![cfg(target_os = "macos")]

use labtether_agent_capabilities::all;
use labtether_agent_config::{Environment, HostFacts, load};

// Fault: the process list (or any page beyond disks and network
// interfaces) is built into the macOS agent, or a capability such as
// terminal or files is advertised, or the network page advertises actions.
#[test]
fn macos_builds_only_the_sandbox_pages() {
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
    let features = all(&load(&env, &host).unwrap().settings);
    let mut handled = features.message_types();
    handled.sort_unstable();
    assert_eq!(handled, ["disk.list", "network.list"]);
    let advertised = features.advertised();
    assert!(
        advertised.capabilities.is_empty(),
        "{:?}",
        advertised.capabilities
    );
    let metadata: Vec<(&str, &str)> = advertised
        .metadata
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        metadata,
        [
            ("cap_network", "list"),
            ("network_action_backend", "none"),
            ("network_backend", "ifconfig"),
        ]
    );
}
