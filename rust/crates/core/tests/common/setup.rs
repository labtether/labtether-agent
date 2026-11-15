//! Agent set-up for the integration tests: a private state folder, settings
//! built through the real loader, short timing, and start and stop.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use labtether_agent_config::{Environment, HostFacts, Settings, load};
use labtether_agent_core::{Agent, StartError, Timing};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// A fresh state folder, removed on drop.
pub struct TestDir(pub PathBuf);

impl TestDir {
    pub fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "lt-core-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn read(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.path(name)).ok()
    }

    pub fn mode(&self, name: &str) -> u32 {
        fs::metadata(self.path(name)).unwrap().permissions().mode() & 0o777
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Settings through the real loader, with every state file in `dir`.
pub fn settings(dir: &TestDir, ws_url: &str, extra: &[(&str, &str)]) -> Settings {
    let path = |name: &str| dir.path(name).display().to_string();
    let mut pairs: Vec<(String, String)> = vec![
        ("LABTETHER_TOKEN_FILE".into(), path("agent-token")),
        (
            "LABTETHER_AGENT_SETTINGS_FILE".into(),
            path("agent-config.json"),
        ),
        ("LABTETHER_DEVICE_KEY_FILE".into(), path("device-key")),
        (
            "LABTETHER_DEVICE_PUBLIC_KEY_FILE".into(),
            path("device-key.pub"),
        ),
        (
            "LABTETHER_DEVICE_FINGERPRINT_FILE".into(),
            path("device-fingerprint"),
        ),
        ("LABTETHER_WS_URL".into(), ws_url.to_owned()),
        ("AGENT_ASSET_ID".into(), "nas01".into()),
        ("AGENT_HEARTBEAT_INTERVAL".into(), "5".into()),
    ];
    if ws_url.starts_with("ws://") {
        pairs.push(("LABTETHER_ALLOW_INSECURE_TRANSPORT".into(), "true".into()));
    }
    pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let host = HostFacts {
        hostname: "nas01.example.com".into(),
        version: "0.1.0-test".into(),
    };
    load(&Environment::from_pairs(pairs), &host)
        .unwrap()
        .settings
}

/// Short timing so keepalive and backoff run in seconds.
pub fn fast_timing() -> Timing {
    Timing {
        ping_interval: Duration::from_millis(100),
        read_deadline: Duration::from_millis(600),
        write_timeout: Duration::from_millis(500),
        handshake_timeout: Duration::from_secs(2),
        backoff_base: Duration::from_millis(50),
        backoff_max: Duration::from_millis(400),
        auth_backoff: Duration::from_secs(2),
        auth_failure_threshold: 3,
        re_enroll_spacing: Duration::from_secs(600),
        rejected_wait: Duration::from_millis(100),
        send_queue: 64,
        min_stable_session: Duration::from_secs(1),
        telemetry_buffer: 60,
    }
}

/// A running agent.
pub struct Running {
    pub agent: Arc<Agent>,
    shutdown: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl Running {
    /// Stops the agent and waits for its loop to end.
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.handle)
            .await
            .expect("the agent stops within 5 s")
            .unwrap();
    }
}

/// Starts an agent with `settings`.
pub async fn start(settings: Settings, timing: Timing) -> Result<Running, StartError> {
    let agent = Agent::start(settings, timing).await?;
    let (shutdown, receiver) = watch::channel(false);
    let handle = tokio::spawn(agent.clone().run(receiver));
    Ok(Running {
        agent,
        shutdown,
        handle,
    })
}

/// Writes `text` to `path`, creating the folder.
pub fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}
