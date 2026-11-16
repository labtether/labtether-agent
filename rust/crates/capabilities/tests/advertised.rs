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

use labtether_agent_capabilities::{Commands, all};
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

/// Advertised values that make the Hub send nothing: it reads the logs it
/// stores (`stored`) and takes the `log.batch` messages the agent sends on
/// its own (`stream`).
const NO_REQUEST: &[(&str, &str)] = &[("cap_logs", "stored"), ("cap_logs", "stream")];

/// What Go sends for a page whose program is missing while it still
/// answers the request: the Hub then never sends that request.
const NO_TOOL: &[(&str, &str)] = &[
    ("cap_services", ""),
    ("cap_packages", ""),
    ("cap_logs", "stored"),
];

/// `(heartbeat capability, request it makes the Hub send)`.
const CAPABILITIES: &[(&str, &str)] = &[
    ("terminal", "terminal.start"),
    ("desktop", "desktop.start"),
    ("files", "file.list"),
    ("power", "power.action"),
    ("webrtc", "webrtc.start"),
];

/// Requests the Hub sends to every Linux agent without any advertisement:
/// disks (no gate), the process list and the users list (added to every
/// agent's capability set, `canonical_helpers.go`).
const UNGATED: &[&str] = &["disk.list", "process.list", "users.list"];

/// Backend keys and the values allowed for them: Go's names. An action
/// backend other than `none` needs the matching `action` value.
const BACKENDS: &[(&str, &[&str])] = &[
    ("log_backend", &["journalctl", "none"]),
    ("network_backend", &["ifconfig"]),
    ("network_action_backend", &["none"]),
    ("service_backend", &["systemd", "none"]),
    (
        "package_backend",
        &[
            "apt-get",
            "dnf",
            "yum",
            "zypper",
            "pacman",
            "apk",
            "dpkg-query",
            "rpm",
            "none",
        ],
    ),
];

/// The features of an agent whose `PATH` is `search_path`.
fn features(search_path: &str) -> labtether_agent_core::Features {
    features_with(search_path, &[])
}

/// As [`features`], with more variables set.
fn features_with(search_path: &str, extra: &[(&str, &str)]) -> labtether_agent_core::Features {
    let dir = std::env::temp_dir().join("lt-capabilities-unused");
    let path = |name: &str| dir.join(name).display().to_string();
    let mut pairs = vec![
        ("LABTETHER_TOKEN_FILE".to_owned(), path("agent-token")),
        (
            "LABTETHER_AGENT_SETTINGS_FILE".to_owned(),
            path("agent-config.json"),
        ),
        ("PATH".to_owned(), search_path.to_owned()),
    ];
    pairs.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let env = Environment::from_pairs(pairs);
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    let settings = load(&env, &host).unwrap().settings;
    #[cfg(target_os = "linux")]
    let commands = Commands::new(labtether_agent_security::CommandPolicy::new(
        &settings.command_security,
        &env,
    ));
    #[cfg(target_os = "macos")]
    let commands = Commands::none();
    all(&settings, &commands)
}

/// A folder of empty executable files named `tools`, removed on drop.
struct Tools(std::path::PathBuf);

impl Tools {
    fn new(name: &str, tools: &[&str]) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lt-tools-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for tool in tools {
            let path = dir.join(tool);
            std::fs::write(&path, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self(dir)
    }

    fn path(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for Tools {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Faults: a page advertised without its handler (the Hub offers a page
// that times out), a handled page the Hub gates on an advertisement left
// unadvertised (the console falls back to its defaults and offers network
// controls this agent lacks), an advertisement in a form Go never sends,
// or a heartbeat capability (terminal, files, ...) this agent cannot serve,
// or a handler for a request the Hub never sends (a page registered under
// the wrong message type is dead code the console cannot reach).
//
// Checked for a host with systemctl, journalctl and a package manager and for one with
// neither. On the second Go sends `cap_services=""`, `cap_packages=""`
// and `cap_logs=stored` with backend `none` while still answering the
// request; that one form is allowed for a handled page.
#[test]
fn advertisements_match_handlers() {
    let full = Tools::new(
        "full",
        &["systemctl", "apt-get", "dpkg-query", "journalctl"],
    );
    let bare = Tools::new("bare", &[]);
    for search_path in [full.path(), bare.path()] {
        check_host(&search_path);
    }
}

fn check_host(search_path: &str) {
    let features = features(search_path);
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
            if NO_REQUEST.contains(&(key.as_str(), token)) {
                continue;
            }
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
    // Go's form for a missing program (`cap_services=""`, `cap_logs=stored`)
    // still names the page, and the agent still answers its request.
    let tool_missing = |key: &str| {
        advertised
            .metadata
            .get(key)
            .is_some_and(|value| NO_TOOL.contains(&(key, value.as_str())))
    };
    let no_tool_form = |request: &&str| {
        CAP_VALUES
            .iter()
            .any(|(key, _, r)| r == request && tool_missing(key))
    };
    for request in &handled {
        assert!(
            implied.contains(request) || UNGATED.contains(request) || no_tool_form(request),
            "{request} is handled but the Hub never sends it to this agent"
        );
    }
    for (key, value, request) in CAP_VALUES {
        if handled.contains(request) && !tool_missing(key) {
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

// Faults: the services or packages page advertises `action` (the Hub then
// offers start, stop, install and remove, which this agent lacks), names
// another backend than Go's, or stops sending Go's empty form on a host
// without the tool.
#[cfg(target_os = "linux")]
#[test]
fn services_and_packages_advertise_list_only() {
    let meta = |search_path: &str, key: &str| {
        features(search_path)
            .advertised()
            .metadata
            .get(key)
            .cloned()
    };
    let full = Tools::new("list-only", &["systemctl", "apt-get", "dpkg-query", "rpm"]);
    let rpm_only = Tools::new("rpm-only", &["rpm"]);
    let bare = Tools::new("none", &[]);
    let rows = [
        (full.path(), ["list", "systemd", "list", "apt-get"]),
        (rpm_only.path(), ["", "none", "list", "rpm"]),
        (bare.path(), ["", "none", "", "none"]),
    ];
    for (search_path, want) in rows {
        let keys = [
            "cap_services",
            "service_backend",
            "cap_packages",
            "package_backend",
        ];
        let got: Vec<Option<String>> = keys.iter().map(|k| meta(&search_path, k)).collect();
        let want: Vec<Option<String>> = want.iter().map(|v| Some((*v).to_owned())).collect();
        assert_eq!(got, want, "{search_path}");
    }
}

// Faults: the logs page advertises `query` or `stream` on a host without
// journalctl (the Hub offers a query that can only fail), drops `stream`
// or `stored` where Go sends them, or names another backend than Go's; the
// live stream is off by default (Go streams unless
// LABTETHER_LOG_STREAM_ENABLED=false) or stays on when turned off.
#[cfg(target_os = "linux")]
#[test]
fn logs_advertise_as_go() {
    let meta = |search_path: &str| {
        let features = features(search_path);
        let get = |key: &str| features.advertised().metadata.get(key).cloned();
        (get("cap_logs"), get("log_backend"))
    };
    let with = Tools::new("journal", &["journalctl"]);
    let without = Tools::new("no-journal", &[]);
    let some = |a: &str, b: &str| (Some(a.to_owned()), Some(b.to_owned()));
    assert_eq!(
        meta(&with.path()),
        some("stored,query,stream", "journalctl")
    );
    assert_eq!(meta(&without.path()), some("stored", "none"));
    assert_eq!(features(&with.path()).producer_names(), ["log-stream"]);
    let off = features_with(&with.path(), &[("LABTETHER_LOG_STREAM_ENABLED", "false")]);
    assert!(off.producer_names().is_empty());
}
