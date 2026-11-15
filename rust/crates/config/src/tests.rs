use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::*;

/// A fresh folder for one test, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "lt-config-{}-{}",
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

fn host() -> HostFacts {
    HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    }
}

fn env_in(dir: &TempDir, extra: &[(&str, &str)]) -> Environment {
    let mut pairs: Vec<(String, String)> = vec![
        (
            "LABTETHER_TOKEN_FILE".into(),
            dir.0.join("agent-token").display().to_string(),
        ),
        (
            "LABTETHER_AGENT_SETTINGS_FILE".into(),
            dir.0.join("agent-config.json").display().to_string(),
        ),
    ];
    pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    Environment::from_pairs(pairs)
}

fn write_settings_file(dir: &TempDir, values: &str) {
    let body = format!(r#"{{"version":1,"values":{values},"updated_at":"2026-11-15T00:00:00Z"}}"#);
    fs::write(dir.0.join("agent-config.json"), body).unwrap();
}

// Fault: a value saved from an earlier Hub push replaces the installer's
// choice, so the agent ignores what the user set at install time.
#[test]
fn environment_wins_over_file_for_hub_managed_settings() {
    let dir = TempDir::new();
    write_settings_file(
        &dir,
        r#"{"heartbeat_interval_sec":"90","log_level":"error"}"#,
    );
    let env = env_in(
        &dir,
        &[
            ("AGENT_HEARTBEAT_INTERVAL", "30s"),
            ("LABTETHER_LOG_LEVEL", "debug"),
        ],
    );
    let settings = load(&env, &host()).unwrap().settings;
    assert_eq!(settings.heartbeat_interval, Duration::from_secs(30));
    assert_eq!(settings.log_level, LogLevel::Debug);

    // Without the environment the file applies.
    let settings = load(&env_in(&dir, &[]), &host()).unwrap().settings;
    assert_eq!(settings.heartbeat_interval, Duration::from_secs(90));
    assert_eq!(settings.log_level, LogLevel::Error);
}

// Fault: `labtether-agent settings set tls_ca_file ...` (which writes the
// file) is silently ignored when the installer also set the variable.
#[test]
fn file_wins_for_local_tls_settings_as_in_go() {
    let dir = TempDir::new();
    write_settings_file(
        &dir,
        r#"{"tls_ca_file":"/etc/labtether/new-ca.pem","tls_skip_verify":"true"}"#,
    );
    let env = env_in(
        &dir,
        &[
            ("LABTETHER_TLS_CA_FILE", "/etc/labtether/old-ca.pem"),
            ("LABTETHER_TLS_SKIP_VERIFY", "false"),
        ],
    );
    let tls = load(&env, &host()).unwrap().settings.tls;
    assert_eq!(
        tls.ca_file,
        Some(PathBuf::from("/etc/labtether/new-ca.pem"))
    );
    assert!(tls.skip_verify);
}

// Fault: after enrollment saved the Hub's CA, a restart does not trust it and
// the agent cannot reconnect to a Hub with its own CA.
#[test]
fn saved_enrollment_ca_is_used_only_when_no_ca_is_configured() {
    let dir = TempDir::new();
    fs::write(dir.0.join("ca.crt"), "pem").unwrap();
    let tls = load(&env_in(&dir, &[]), &host()).unwrap().settings.tls;
    assert_eq!(tls.ca_file, Some(dir.0.join("ca.crt")));

    let env = env_in(&dir, &[("LABTETHER_TLS_CA_FILE", "/srv/proxy-ca.pem")]);
    let tls = load(&env, &host()).unwrap().settings.tls;
    assert_eq!(tls.ca_file, Some(PathBuf::from("/srv/proxy-ca.pem")));
}

// Fault: a typo in LABTETHER_TLS_CA_ONLY quietly falls back to the system
// roots, which the option exists to exclude.
#[test]
fn ca_only_that_is_not_a_boolean_stops_start() {
    let dir = TempDir::new();
    let env = env_in(&dir, &[("LABTETHER_TLS_CA_ONLY", "yes please")]);
    assert!(matches!(
        load(&env, &host()),
        Err(ConfigError::CaOnlyNotBoolean(_))
    ));
    let env = env_in(&dir, &[("LABTETHER_TLS_CA_ONLY", "true")]);
    assert!(load(&env, &host()).unwrap().settings.tls.ca_only);
}

// Fault: a plain ws:// address sends the agent token unencrypted although
// the user never opted in to insecure transport.
#[test]
fn insecure_hub_address_is_upgraded_without_the_opt_in() {
    let dir = TempDir::new();
    let env = env_in(
        &dir,
        &[("LABTETHER_WS_URL", "ws://192.0.2.10:8443/ws/agent")],
    );
    assert_eq!(
        load(&env, &host()).unwrap().settings.ws_url,
        "wss://192.0.2.10:8443/ws/agent"
    );
    let env = env_in(
        &dir,
        &[
            ("LABTETHER_WS_URL", "http://192.0.2.10:8080/ws/agent"),
            ("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true"),
        ],
    );
    assert_eq!(
        load(&env, &host()).unwrap().settings.ws_url,
        "ws://192.0.2.10:8080/ws/agent"
    );
}

// Fault: the interval accepts values the Hub would flood on, or rejects the
// forms installers write ("30", "30s", "1m").
#[test]
fn heartbeat_interval_parses_go_forms_and_is_clamped() {
    let cases = [
        ("30", 30),
        ("30s", 30),
        ("1m", 60),
        ("1m30s", 90),
        ("0", 5),
        ("2", 5),
        ("1h", 600),
        ("soon", 20),
    ];
    for (raw, want) in cases {
        let got = parse_duration_or(
            Some(raw),
            Duration::from_secs(20),
            MIN_HEARTBEAT,
            MAX_HEARTBEAT,
        );
        assert_eq!(got, Duration::from_secs(want), "{raw}");
    }
}

// Fault: the token sources are read in another order than Go's (variable,
// then file), or the token reaches a log line through `Debug`.
#[test]
fn enrollment_token_comes_from_environment_then_file() {
    let dir = TempDir::new();
    let file = dir.0.join("enroll.token");
    fs::write(&file, "  file-token \n").unwrap();
    let env = env_in(
        &dir,
        &[("LABTETHER_ENROLLMENT_TOKEN_FILE", file.to_str().unwrap())],
    );
    let enrollment = load(&env, &host()).unwrap().settings.enrollment.unwrap();
    assert_eq!(enrollment.token.expose(), "file-token");
    assert_eq!(enrollment.file, Some(file.clone()));

    let env = env_in(
        &dir,
        &[
            ("LABTETHER_ENROLLMENT_TOKEN", "env-token"),
            ("LABTETHER_ENROLLMENT_TOKEN_FILE", file.to_str().unwrap()),
        ],
    );
    let enrollment = load(&env, &host()).unwrap().settings.enrollment.unwrap();
    assert_eq!(enrollment.token.expose(), "env-token");
    assert_eq!(enrollment.file, None);
    assert!(!format!("{enrollment:?}").contains("env-token"));
}
