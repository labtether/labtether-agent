//! The Docker settings against Go's `LoadConfig` rules. Values are made up.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::{DockerMode, Environment, HostFacts, load};

fn docker(env: &[(&str, &str)], file: Option<&str>) -> (DockerMode, String, Duration) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("lt-config-docker-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let settings_file = dir.join(format!(
        "agent-config-{}.json",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if let Some(values) = file {
        std::fs::write(
            &settings_file,
            format!(r#"{{"version":1,"values":{values}}}"#),
        )
        .unwrap();
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
    let docker = load(&Environment::from_pairs(pairs), &host)
        .unwrap()
        .settings
        .docker;
    let _ = std::fs::remove_file(&settings_file);
    let _ = std::fs::remove_dir(&dir);
    (docker.mode, docker.endpoint, docker.discovery_interval)
}

const SOCKET: &str = "/var/run/docker.sock";

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// Faults: a value saved in agent-config.json from an earlier Hub push
// replaces the installer's choice in the environment; low-power mode does
// not pin the interval; `DOCKER_HOST` is read (Go ignores it, so the two
// agents would read different engines); a bad endpoint is kept instead of
// Go's default socket; an interval outside 5 s to 1 h is used.
#[test]
fn docker_settings_follow_go() {
    use DockerMode::{Auto, Off, On};
    let file = r#"{"docker_enabled":"false","docker_endpoint":"unix:///srv/docker.sock","docker_discovery_interval_sec":"45"}"#;
    assert_eq!(docker(&[], None), (Auto, SOCKET.into(), secs(30)));
    assert_eq!(
        docker(&[], Some(file)),
        (Off, "unix:///srv/docker.sock".into(), secs(45))
    );
    assert_eq!(
        docker(
            &[
                ("LABTETHER_DOCKER_ENABLED", " TRUE "),
                ("LABTETHER_DOCKER_SOCKET", "/run/docker.sock")
            ],
            Some(file)
        ),
        (On, "/run/docker.sock".into(), secs(45))
    );
    assert_eq!(
        docker(&[("LABTETHER_LOW_POWER_MODE", "true")], Some(file)).2,
        secs(300)
    );
    assert_eq!(
        docker(&[("LABTETHER_DOCKER_DISCOVERY_INTERVAL", "10")], Some(file)).2,
        secs(10)
    );
    assert_eq!(
        docker(&[("LABTETHER_DOCKER_DISCOVERY_INTERVAL", "2s")], None).2,
        secs(5)
    );
    assert_eq!(
        docker(&[("LABTETHER_DOCKER_DISCOVERY_INTERVAL", "2h")], None).2,
        secs(3600)
    );
    assert_eq!(
        docker(&[], Some(r#"{"docker_discovery_interval_sec":"4"}"#)).2,
        secs(30)
    );
    assert_eq!(
        docker(&[("LABTETHER_DOCKER_ENABLED", "maybe")], None).0,
        Auto
    );
    assert_eq!(
        docker(&[("DOCKER_HOST", "unix:///other.sock")], None).1,
        SOCKET
    );
    for (raw, want) in [
        ("//server/docker.sock", SOCKET),
        ("unix://relative.sock", SOCKET),
        ("tcp://192.0.2.10:2375", SOCKET),
        ("npipe:////./pipe/../engine", SOCKET),
        ("UNIX:// /srv/docker.sock", "unix:///srv/docker.sock"),
        (
            "npipe:////./pipe/docker_engine",
            "npipe:////./pipe/docker_engine",
        ),
    ] {
        assert_eq!(
            docker(&[("LABTETHER_DOCKER_SOCKET", raw)], None).1,
            want,
            "{raw}"
        );
    }
}
