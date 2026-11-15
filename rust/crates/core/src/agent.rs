//! Start-up and the shared state every connection uses.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use labtether_agent_config::{EnrollmentToken, Settings};
use rustls::ClientConfig;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::credential::{self, IdentityCell};
use crate::flow;
use crate::heartbeat::HeartbeatTemplate;
use crate::identity::{self, DeviceIdentity, IdentityError};
use crate::state::StateFiles;
use crate::timing::Timing;
use crate::tls::{self, TlsError, TrustMode};

/// Why the agent could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("{0}")]
    Tls(#[from] TlsError),
    #[error("device key: {0}")]
    Identity(#[from] IdentityError),
    #[error(
        "no Hub address: set LABTETHER_WS_URL (or LABTETHER_API_BASE_URL with an enrollment token)"
    )]
    NoHubAddress,
}

/// A staged one-use token kept for re-enrollment, and when it was last tried.
#[derive(Debug, Default)]
pub(crate) struct ReEnroll {
    pub token: Option<EnrollmentToken>,
    pub last_attempt: Option<Instant>,
}

/// State shared by the reconnect loop, the session and the handlers.
#[derive(Debug)]
pub struct Agent {
    pub(crate) settings: Settings,
    pub(crate) device: DeviceIdentity,
    pub(crate) files: StateFiles,
    pub(crate) identity: IdentityCell,
    pub(crate) tls: Arc<ClientConfig>,
    pub(crate) timing: Timing,
    pub(crate) heartbeat: HeartbeatTemplate,
    /// An admin rejected the pending request; wait for a token.
    pub(crate) rejected: AtomicBool,
    pub(crate) re_enroll: Mutex<ReEnroll>,
}

impl Agent {
    /// Checks TLS, loads or creates the device key, picks the credential and
    /// enrolls when a one-use token is staged and no token is saved.
    pub async fn start(settings: Settings, timing: Timing) -> Result<Arc<Self>, StartError> {
        tls::validate(&settings.tls)?;
        let mut tls_settings = settings.tls.clone();
        log_trust(&tls_settings);
        let device = identity::ensure(&settings)?;
        let files = StateFiles::new(&settings.token_file, settings.allow_insecure_transport);
        let startup = credential::startup(&settings, &files);
        let mut identity = startup.identity;
        let mut enrollment = startup.enrollment;

        if identity.token.is_none()
            && let Some(staged) = enrollment.as_ref()
        {
            let tls_config = tls::client_config(&tls_settings)?;
            match flow::enroll_at_start(&settings, &files, &device, &tls_config, &identity, staged)
                .await
            {
                Ok(done) => {
                    identity = done.identity;
                    enrollment = None;
                    if let Some(ca_file) = done.saved_ca {
                        tls_settings.ca_file = Some(ca_file);
                    }
                }
                Err(error) => log::error!("enrollment failed: {error}"),
            }
        }
        if identity.ws_url.is_empty() {
            return Err(StartError::NoHubAddress);
        }
        let re_enroll = ReEnroll {
            token: enrollment.filter(|_| identity.token.is_some()),
            last_attempt: None,
        };
        let heartbeat = HeartbeatTemplate::new(&settings, &device);
        Ok(Arc::new(Self {
            tls: tls::client_config(&tls_settings)?,
            settings,
            device,
            files,
            identity: IdentityCell::new(identity),
            timing,
            heartbeat,
            rejected: AtomicBool::new(false),
            re_enroll: Mutex::new(re_enroll),
        }))
    }

    /// Keeps the agent connected until `shutdown` turns true.
    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) {
        crate::reconnect::run(self, shutdown).await;
    }

    pub(crate) fn re_enroll_state(&self) -> MutexGuard<'_, ReEnroll> {
        self.re_enroll
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn waiting_after_rejection(&self) -> bool {
        self.rejected.load(Ordering::Relaxed) && self.identity.snapshot().token.is_none()
    }

    /// The asset ID in use now (the Hub's, once known).
    pub fn asset_id(&self) -> String {
        self.identity.snapshot().asset_id
    }
}

fn log_trust(tls_settings: &labtether_agent_config::TlsSettings) {
    match tls::trust_mode(tls_settings) {
        TrustMode::CaOnly => log::info!(
            "Hub connections trust only the CA in {} (LABTETHER_TLS_CA_ONLY=true)",
            tls_settings
                .ca_file
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        TrustMode::SkipVerify => log::warn!(
            "TLS certificate verification is off (LABTETHER_TLS_SKIP_VERIFY=true). Set LABTETHER_TLS_CA_FILE to the Hub's CA to turn it back on."
        ),
        TrustMode::SystemRootsAndCa if tls_settings.skip_verify => {
            log::info!("the configured TLS CA takes priority; LABTETHER_TLS_SKIP_VERIFY is ignored")
        }
        TrustMode::SystemRootsAndCa | TrustMode::SystemRoots => {}
    }
}
