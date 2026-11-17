//! The web service settings against Go's `LoadConfig` rules. Values are
//! made up.

use std::sync::atomic::{AtomicU32, Ordering};

use super::{Environment, HostFacts, PortScanSettings, WebServiceSettings, load};

fn settings(env: &[(&str, &str)], file: Option<&str>) -> WebServiceSettings {
    // A folder per call: the tests run at once and each removes its own.
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lt-config-web-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let settings_file = dir.join("agent-config.json");
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
    let loaded = load(&Environment::from_pairs(pairs), &host)
        .unwrap()
        .settings
        .web_services;
    let _ = std::fs::remove_file(&settings_file);
    let _ = std::fs::remove_dir(&dir);
    loaded
}

fn web(env: &[(&str, &str)], file: Option<&str>) -> (u64, bool) {
    let loaded = settings(env, file);
    (loaded.interval.as_secs(), loaded.docker_enabled)
}

fn scan(env: &[(&str, &str)], file: Option<&str>) -> (bool, bool, Vec<u16>) {
    let PortScanSettings {
        enabled,
        include_listening,
        ports,
    } = settings(env, file).port_scan;
    (enabled, include_listening, ports)
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

// Faults: the scan or its listening ports off by default, or on in
// low-power mode; Go's older variables not read (`..._PORTSCAN_DISABLED`
// turns the scan off only for true, 1 or on; `..._INCLUDE_LISTENING`
// only when it reads as a switch; `..._PORTSCAN_PORTS` when the new list
// is not set); a value saved in agent-config.json from an earlier Hub
// push replacing a choice made in the environment (any of its names set,
// or low-power mode for the two switches), or not read at all; a bad
// list kept in part instead of Go's default ports.
#[test]
fn port_scan_settings_follow_go() {
    const ON: &str = "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_ENABLED";
    const OFF: &str = "LABTETHER_WEBSVC_PORTSCAN_DISABLED";
    const LISTENING: &str = "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_INCLUDE_LISTENING";
    const OLD_LISTENING: &str = "LABTETHER_WEBSVC_PORTSCAN_INCLUDE_LISTENING";
    const PORTS: &str = "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_PORTS";
    const OLD_PORTS: &str = "LABTETHER_WEBSVC_PORTSCAN_PORTS";
    const LOW: (&str, &str) = ("LABTETHER_LOW_POWER_MODE", "true");
    let file = Some(
        r#"{"services_discovery_port_scan_enabled":"false",
            "services_discovery_port_scan_include_listening":"false",
            "services_discovery_port_scan_ports":" 8443, 80 "}"#,
    );
    let file_on = Some(
        r#"{"services_discovery_port_scan_enabled":"true",
            "services_discovery_port_scan_include_listening":"1"}"#,
    );
    assert_eq!(scan(&[], None), (true, true, vec![]));
    assert_eq!(scan(&[], file), (false, false, vec![80, 8443]));
    assert_eq!(scan(&[LOW], None), (false, false, vec![]));
    assert_eq!(scan(&[LOW], file_on), (false, false, vec![]));
    assert_eq!(
        scan(&[LOW, (ON, "1"), (LISTENING, "t")], None),
        (true, true, vec![])
    );
    assert_eq!(scan(&[(ON, "false")], file_on), (false, true, vec![]));
    assert_eq!(scan(&[(ON, "maybe")], file), (true, false, vec![80, 8443]));
    for (raw, enabled) in [
        ("TRUE", false),
        ("on", false),
        ("1", false),
        ("yes", true),
        ("t", true),
    ] {
        assert_eq!(scan(&[(ON, "false"), (OFF, raw)], None).0, enabled, "{raw}");
        assert_eq!(scan(&[(OFF, raw)], file_on).0, enabled, "{raw}");
    }
    assert!(scan(&[(LISTENING, "false"), (OLD_LISTENING, "TRUE")], None).1);
    assert!(!scan(&[(LISTENING, "false"), (OLD_LISTENING, "maybe")], None).1);
    assert!(scan(&[(OLD_LISTENING, "maybe")], file).1);
    assert_eq!(scan(&[(PORTS, "9000;8080 9000")], file).2, vec![8080, 9000]);
    assert_eq!(scan(&[(PORTS, "80,abc")], file).2, Vec::<u16>::new());
    assert_eq!(scan(&[(OLD_PORTS, "+3000")], file).2, vec![3000]);
    assert_eq!(
        scan(&[(PORTS, "81"), (OLD_PORTS, "3000")], None).2,
        vec![81]
    );
    assert_eq!(scan(&[(PORTS, "  ")], file).2, vec![80, 8443]);
    let bad = Some(r#"{"services_discovery_port_scan_ports":"80,abc"}"#);
    assert_eq!(scan(&[], bad).2, Vec::<u16>::new());
}
