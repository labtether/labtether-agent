//! The heartbeat's words must be the Hub's words for exactly the requests
//! this agent answers, in the Linux and the macOS build. The agent says
//! `agent_capability_mode=explicit`, so the Hub sends it only what it
//! advertises and refuses everything else with 422 `agent_unsupported`
//! (the Hub's `internal/agentcaps/agentcaps.go`). A handled request without
//! its word is a page the Hub never offers; a word without a handler is a
//! page the Hub offers that times out.

use std::collections::BTreeSet;

use labtether_agent_capabilities::{Commands, all};
use labtether_agent_config::{Environment, HostFacts, load};

/// The Hub's rule, copied from `messageNeeds` in the Hub's
/// `internal/agentcaps/agentcaps.go`: `(request, key, token)`. Only the
/// rows of the data pages and the web services' sync: the Hub's other
/// words (the heartbeat list's `terminal`, `files`, `desktop`, `webrtc`,
/// `power`; `cap_wol`, `cap_ssh_keys`, `cap_docker`, `cap_commands`,
/// `cap_settings`, `cap_updates`) have no handler here, so any of them in
/// the heartbeat fails as unknown.
const HUB_WORDS: &[(&str, &str, &str)] = &[
    ("disk.list", "cap_disks", "list"),
    ("process.list", "cap_processes", "list"),
    ("process.kill", "cap_processes", "kill"),
    ("service.list", "cap_services", "list"),
    ("service.action", "cap_services", "action"),
    ("network.list", "cap_network", "list"),
    ("network.action", "cap_network", "action"),
    ("package.list", "cap_packages", "list"),
    ("package.action", "cap_packages", "action"),
    ("cron.list", "cap_schedules", "list"),
    ("users.list", "cap_users", "list"),
    ("journal.query", "cap_logs", "query"),
    ("webservice.sync", "cap_web_services", "sync"),
];

/// Advertised tokens that make the Hub send nothing: it reads the logs it
/// stores (`stored`) and takes the `log.batch` messages the agent sends on
/// its own (`stream`).
const NO_REQUEST: &[(&str, &str)] = &[("cap_logs", "stored"), ("cap_logs", "stream")];

/// Host keys and the values allowed for them: Go's names.
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
        // The Docker page probes the test host's engine; these tests are
        // about the words of the pages that answer requests.
        ("LABTETHER_DOCKER_ENABLED".to_owned(), "false".to_owned()),
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

// Faults: a handled request whose word is missing or misspelt (the Hub
// refuses a page this agent answers), a word with no handler (the Hub
// offers a page that times out), a word or key the Hub does not know, an
// empty `cap_*` value, or a heartbeat without `agent_capability_mode=explicit`
// (the Hub then offers every page, as to a Go agent). Checked for a host
// with every tool, one with only `rpm` and one with none; on macOS the
// `PATH` changes nothing.
#[test]
fn every_handler_has_its_word_and_every_word_a_handler() {
    let full = Tools::new(
        "full",
        &["systemctl", "apt-get", "dpkg-query", "journalctl"],
    );
    let rpm_only = Tools::new("rpm-only", &["rpm"]);
    let bare = Tools::new("bare", &[]);
    for search_path in [full.path(), rpm_only.path(), bare.path()] {
        check_host(&search_path);
    }
}

fn check_host(search_path: &str) {
    let features = features(search_path);
    let handled: BTreeSet<&str> = features.message_types().into_iter().collect();
    let metadata = features.advertised().metadata.clone();
    let mode = metadata.get("agent_capability_mode").map(String::as_str);
    assert_eq!(mode, Some("explicit"), "{search_path}");
    for request in &handled {
        let (_, key, token) = HUB_WORDS
            .iter()
            .find(|(r, _, _)| r == request)
            .unwrap_or_else(|| panic!("{request} is handled but the Hub has no word for it"));
        let value = metadata.get(*key).map_or("", String::as_str);
        assert!(
            value.split(',').any(|t| t == *token),
            "{request} is handled but {key}={value:?} does not say {token}"
        );
    }
    for (key, value) in &metadata {
        if key == "agent_capability_mode" || key == "agent_edition" {
            continue;
        }
        if let Some((_, allowed)) = BACKENDS.iter().find(|(name, _)| name == key) {
            assert!(allowed.contains(&value.as_str()), "{key}={value}");
            continue;
        }
        assert!(key.starts_with("cap_"), "unknown advertised key {key}");
        for token in value.split(',') {
            if NO_REQUEST.contains(&(key.as_str(), token)) {
                continue;
            }
            let (request, _, _) = HUB_WORDS
                .iter()
                .find(|(_, k, t)| k == key && *t == token)
                .unwrap_or_else(|| panic!("{key}={value:?}: {token:?} is not a Hub word"));
            assert!(
                handled.contains(request),
                "{key}={token} is advertised but {request} has no handler"
            );
        }
    }
}

/// The advertisement's keys and values, sorted by key.
#[cfg(target_os = "linux")]
fn words(search_path: &str) -> Vec<(String, String)> {
    features(search_path)
        .advertised()
        .metadata
        .clone()
        .into_iter()
        .collect()
}

/// Checks a Linux host's whole advertisement and its handlers: what every
/// Linux host sends and handles, plus `words_too` and `handled_too`.
#[cfg(target_os = "linux")]
fn assert_linux_host(tools: &Tools, words_too: &[(&str, &str)], handled_too: &[&str]) {
    let mut want: Vec<(String, String)> = [
        ("agent_capability_mode", "explicit"),
        ("cap_disks", "list"),
        ("cap_network", "list"),
        ("cap_processes", "list"),
        ("cap_schedules", "list"),
        ("cap_users", "list"),
        ("cap_web_services", "sync"),
        ("network_action_backend", "none"),
        ("network_backend", "ifconfig"),
    ]
    .iter()
    .chain(words_too)
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    want.sort();
    assert_eq!(words(&tools.path()), want, "{}", tools.path());
    let mut handled = features(&tools.path()).message_types();
    handled.sort_unstable();
    let mut want_handled = vec![
        "cron.list",
        "disk.list",
        "network.list",
        "process.list",
        "users.list",
        "webservice.sync",
    ];
    want_handled.extend(handled_too);
    want_handled.sort_unstable();
    assert_eq!(handled, want_handled, "{}", tools.path());
}

// Faults: the Linux agent leaves out a page it answers or names one it
// does not (`action` for services, packages or network; `kill`; a page
// whose tool is missing; the web services' sync, which the Hub then
// refuses with 422), sends `cap_services=""` or `cap_packages=""`
// (Go's form, which the console reads as supported), sends an edition (the
// console would say "Monitoring only"), or names another backend than Go's.
#[cfg(target_os = "linux")]
#[test]
fn linux_sends_the_words_of_the_pages_it_answers() {
    let full = Tools::new(
        "words-full",
        &["systemctl", "apt-get", "dpkg-query", "journalctl"],
    );
    assert_linux_host(
        &full,
        &[
            ("cap_logs", "stored,query,stream"),
            ("cap_packages", "list"),
            ("cap_services", "list"),
            ("log_backend", "journalctl"),
            ("package_backend", "apt-get"),
            ("service_backend", "systemd"),
        ],
        &["journal.query", "package.list", "service.list"],
    );
    let rpm_only = Tools::new("words-rpm", &["rpm"]);
    assert_linux_host(
        &rpm_only,
        &[
            ("cap_logs", "stored"),
            ("cap_packages", "list"),
            ("log_backend", "none"),
            ("package_backend", "rpm"),
            ("service_backend", "none"),
        ],
        &["package.list"],
    );
    let bare = Tools::new("words-bare", &[]);
    assert_linux_host(
        &bare,
        &[
            ("cap_logs", "stored"),
            ("log_backend", "none"),
            ("package_backend", "none"),
            ("service_backend", "none"),
        ],
        &[],
    );
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
    // The web service report runs on every Linux build, as Go's.
    assert_eq!(
        features(&with.path()).producer_names(),
        ["web-services", "log-stream"]
    );
    let off = features_with(&with.path(), &[("LABTETHER_LOG_STREAM_ENABLED", "false")]);
    assert_eq!(off.producer_names(), ["web-services"]);
}
