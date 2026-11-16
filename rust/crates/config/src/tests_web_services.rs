//! The web service settings against Go's `LoadConfig` rules. Values are
//! made up.

use std::sync::atomic::{AtomicU32, Ordering};

use super::{Environment, HostFacts, WebServiceSettings, load};

fn web(env: &[(&str, &str)], file: Option<&str>) -> (u64, bool) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("lt-config-web-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let settings_file = dir.join(format!(
        "agent-config-{}.json",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if let Some(values) = file {
        let text = format!(r#"{{"version":1,"values":{values}}}"#);
        std::fs::write(&settings_file, text).unwrap();
    }
    let mut pairs = vec![
        (
            "LABTETHER_TOKEN_FILE".to_owned(),
            dir.join("agent-token").display().to_string(),
        ),
        (
            "LABTETHER_AGENT_SETTINGS_FILE".to_owned(),
            settings_file.display().to_string(),
        ),
    ];
    pairs.extend(env.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    let WebServiceSettings {
        interval,
        docker_enabled,
    } = load(&Environment::from_pairs(pairs), &host)
        .unwrap()
        .settings
        .web_services;
    let _ = std::fs::remove_file(&settings_file);
    let _ = std::fs::remove_dir(&dir);
    (interval.as_secs(), docker_enabled)
}

// Faults: the report comes at another pace than Go's (not 60 s, not
// 10 min in low-power mode, outside 30 s to 6 h, or Go's duration text
// misread); a value saved in agent-config.json from an earlier Hub push
// replaces the installer's choice in the environment, or is not read at
// all; an unreadable environment value turns the Docker source off where
// Go keeps it on.
#[test]
fn web_service_settings_follow_go() {
    const VAR: &str = "LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED";
    const INTERVAL: &str = "LABTETHER_SERVICES_DISCOVERY_INTERVAL";
    let off = Some(r#"{"services_discovery_docker_enabled":" false "}"#);
    assert_eq!(web(&[], None), (60, true));
    assert_eq!(web(&[("LABTETHER_LOW_POWER_MODE", "1")], None), (600, true));
    assert_eq!(web(&[(INTERVAL, "90")], None).0, 90);
    assert_eq!(web(&[(INTERVAL, "2m30s")], None).0, 150);
    assert_eq!(web(&[(INTERVAL, "5")], None).0, 30);
    assert_eq!(web(&[(INTERVAL, "-1")], None).0, 30);
    assert_eq!(web(&[(INTERVAL, "7h")], None).0, 6 * 3600);
    assert_eq!(web(&[(INTERVAL, "soon")], None).0, 60);
    assert_eq!(web(&[], off), (60, false));
    assert_eq!(web(&[(VAR, "TRUE")], off), (60, true));
    assert_eq!(web(&[(VAR, "maybe")], off), (60, true));
    assert_eq!(web(&[(VAR, "0")], None), (60, false));
    let unreadable = Some(r#"{"services_discovery_docker_enabled":"no"}"#);
    assert_eq!(web(&[], unreadable), (60, true));
}
