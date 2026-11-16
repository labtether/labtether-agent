//! Start-up and the shared state every connection uses.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use labtether_agent_config::{EnrollmentToken, Settings};
use rustls::ClientConfig;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::alerts::AlertCache;
use crate::credential::{self, IdentityCell};
use crate::features::Features;
use crate::flow;
use crate::heartbeat::{HeartbeatTemplate, LinkStats};
use crate::identity::{self, DeviceIdentity, IdentityError};
use crate::intervals::IntervalControl;
use crate::link_status::{LinkStatus, TOKEN_PERSISTENCE_FAILED};
use crate::outbox::Outbox;
use crate::producers::Stop;
use crate::state::StateFiles;
use crate::status::{LatestCell, StartTime};
use crate::timing::Timing;
use crate::tls::{self, TlsError, TrustMode};
use crate::workers::Workers;

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
    /// Collect and heartbeat intervals, changed by the Hub's `config.update`.
    pub(crate) intervals: IntervalControl,
    /// The send queue of the current connection, set while one with a token
    /// is open. The telemetry loop sends through it.
    pub(crate) link: watch::Sender<Option<Outbox>>,
    pub(crate) stats: Arc<LinkStats>,
    /// An admin rejected the pending request; wait for a token.
    pub(crate) rejected: AtomicBool,
    pub(crate) re_enroll: Mutex<ReEnroll>,
    /// The feature handlers each connection registers.
    pub(crate) features: Features,
    /// Request handler slots, shared by every connection as in Go.
    pub(crate) workers: Workers,
    /// The connection state the local status page shows.
    pub(crate) link_status: LinkStatus,
    /// The latest telemetry sample, for the local pages.
    pub(crate) latest: LatestCell,
    /// Alerts the Hub pushed, for the local status page.
    pub(crate) alerts: AlertCache,
    pub(crate) started: StartTime,
}

impl Agent {
    /// An agent with no features: it connects and reports telemetry only.
    pub async fn start(settings: Settings, timing: Timing) -> Result<Arc<Self>, StartError> {
        Self::start_with(settings, timing, Features::new()).await
    }

    /// Checks TLS, loads or creates the device key, picks the credential and
    /// enrolls when a one-use token is staged and no token is saved.
    /// `features` adds the request handlers and what the heartbeat
    /// advertises.
    pub async fn start_with(
        settings: Settings,
        timing: Timing,
        features: Features,
    ) -> Result<Arc<Self>, StartError> {
        let started = StartTime::now();
        tls::validate(&settings.tls)?;
        let mut tls_settings = settings.tls.clone();
        log_trust(&tls_settings);
        let device = identity::ensure(&settings)?;
        let files = StateFiles::new(&settings.token_file, settings.allow_insecure_transport);
        let startup = credential::startup(&settings, &files);
        let mut identity = startup.identity;
        let mut enrollment = startup.enrollment;
        let link_status = LinkStatus::default();

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
                    // Go's start path reports only the token write; a
                    // failed clean-up of the one-use token is logged.
                    if done.memory_only {
                        link_status.set_persistence(TOKEN_PERSISTENCE_FAILED);
                    }
                }
                Err(error) => {
                    log::error!("enrollment failed: {error}");
                    link_status.set_credential_rejected(error.is_token_rejected());
                    if let Some(words) = error.hub_words() {
                        link_status.set_refusal(words);
                    }
                }
            }
        }
        if identity.ws_url.is_empty() {
            return Err(StartError::NoHubAddress);
        }
        let re_enroll = ReEnroll {
            token: enrollment.filter(|_| identity.token.is_some()),
            last_attempt: None,
        };
        let heartbeat = HeartbeatTemplate::new(
            &settings,
            &device,
            &features.advertised(),
            features.connector_sources(),
        );
        let workers = Workers::new(timing.request_workers);
        let intervals = IntervalControl::new(&settings);
        Ok(Arc::new(Self {
            tls: tls::client_config(&tls_settings)?,
            settings,
            device,
            files,
            identity: IdentityCell::new(identity),
            timing,
            heartbeat,
            intervals,
            link: watch::Sender::new(None),
            stats: Arc::new(LinkStats::default()),
            rejected: AtomicBool::new(false),
            re_enroll: Mutex::new(re_enroll),
            features,
            workers,
            link_status,
            latest: LatestCell::new(started.wall),
            alerts: AlertCache::default(),
            started,
        }))
    }

    /// Keeps the agent connected and sampling until `shutdown` turns true.
    /// Both loops run on the caller's task, so no thread is added.
    /// The producers run on their own threads; when both loops end they
    /// are stopped and waited for, at most the write timeout.
    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) {
        let stop = Stop::new();
        let producers = crate::producers::start(&self, &stop);
        let telemetry = crate::telemetry::run(&self, shutdown.clone());
        let connection = crate::reconnect::run(self.clone(), shutdown);
        tokio::join!(telemetry, connection);
        stop.stop();
        crate::producers::join(producers, self.timing.write_timeout).await;
    }

    pub(crate) fn re_enroll_state(&self) -> MutexGuard<'_, ReEnroll> {
        self.re_enroll
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn waiting_after_rejection(&self) -> bool {
        self.rejected.load(Ordering::Relaxed) && self.identity.snapshot().token.is_none()
    }

    /// Request handlers running now.
    pub fn workers_running(&self) -> usize {
        self.workers.running()
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
