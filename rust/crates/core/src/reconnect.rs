//! The reconnect loop, ported from Go's `reconnectLoop`.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::agent::Agent;
use crate::backoff::{AuthWait, Backoff};
use crate::connection::{self, ConnectError};
use crate::flow;
use crate::late_enroll::{self, LateEnrollment};
use crate::link_status::FailureKind;
use crate::session::{self, SessionEnd};
use crate::timing::jitter;

/// Waits `duration`; false when the agent is stopping.
async fn wait(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => true,
        _ = shutdown.changed() => false,
    }
}

/// Tries re-enrollment after the long wait starts, at most once per spacing.
/// Returns true when a new token is in use.
async fn try_re_enroll(agent: &Agent) -> bool {
    let staged = {
        let mut state = agent.re_enroll_state();
        let due = state
            .last_attempt
            .is_none_or(|last| last.elapsed() > agent.timing.re_enroll_spacing);
        let Some(token) = state.token.clone().filter(|_| due) else {
            return false;
        };
        state.last_attempt = Some(Instant::now());
        token
    };
    log::info!("trying re-enrollment after repeated refused credentials");
    match flow::re_enroll(agent, &staged).await {
        Ok(warning) => {
            agent.re_enroll_state().token = None;
            // Go: the warning is set in the re-enrollment, then
            // `updateToken` clears the failure, the refusal and the
            // rejection.
            agent.link_status.set_persistence(&warning);
            agent.link_status.token_replaced();
            agent
                .rejected
                .store(false, std::sync::atomic::Ordering::Relaxed);
            log::info!("re-enrollment succeeded; connecting again");
            true
        }
        Err(error) => {
            log::warn!("re-enrollment failed: {error}");
            if let Some(words) = error.hub_words() {
                agent.link_status.set_refusal(words);
            }
            false
        }
    }
}

/// The wait after a failed attempt, or `None` to retry at once.
async fn after_failure(
    agent: &Agent,
    backoff: &mut Backoff,
    error: &ConnectError,
) -> Option<Duration> {
    if error.is_auth() {
        return match backoff.auth_refused() {
            AuthWait::Retry(wait) => {
                log::warn!(
                    "credentials refused ({}/{}), retrying in {wait:?}: {error}",
                    backoff.auth_failures(),
                    agent.timing.auth_failure_threshold
                );
                Some(wait)
            }
            AuthWait::Long(wait) => {
                log::warn!(
                    "credentials refused {} times in a row, waiting {wait:?}: {error}",
                    backoff.auth_failures()
                );
                if try_re_enroll(agent).await {
                    backoff.reset();
                    return None;
                }
                Some(wait)
            }
        };
    }
    let first = backoff.at_base() && error.is_untrusted();
    let wait = backoff.transient();
    log::warn!("connect failed, retrying in {wait:?}: {error}");
    if first {
        if agent.settings.tls.ca_only {
            log::warn!(
                "the Hub's certificate is not signed by the CA in LABTETHER_TLS_CA_FILE, and LABTETHER_TLS_CA_ONLY=true trusts nothing else"
            );
        } else {
            log::warn!("set LABTETHER_TLS_CA_FILE to the Hub's CA certificate");
        }
    }
    Some(wait)
}

/// Keeps one connection open until `shutdown` turns true.
pub async fn run(agent: Arc<Agent>, shutdown: watch::Receiver<bool>) {
    keep_connected(&agent, shutdown).await;
    agent.link_status.loop_stopped();
}

async fn keep_connected(agent: &Arc<Agent>, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = Backoff::new(&agent.timing, jitter);
    loop {
        if *shutdown.borrow() {
            return;
        }
        if agent.waiting_after_rejection() {
            if !wait(agent.timing.rejected_wait, &mut shutdown).await {
                return;
            }
            continue;
        }
        // A staged token that has not reached the Hub yet is used before a
        // socket without a token would ask an admin for approval.
        match late_enroll::try_enroll(agent).await {
            LateEnrollment::Connect => {}
            LateEnrollment::Enrolled => backoff.reset(),
            LateEnrollment::Unanswered(error) => {
                let duration = backoff.transient();
                log::warn!("enrollment did not reach the Hub, retrying in {duration:?}: {error}");
                if !wait(duration, &mut shutdown).await {
                    return;
                }
                continue;
            }
        }
        match connection::connect(agent).await {
            Ok(connection) => {
                agent
                    .stats
                    .connects
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                agent.link_status.opened(connection.pending_enrollment);
                backoff.connected();
                let opened = Instant::now();
                let end = session::run(agent, connection, &mut shutdown).await;
                agent.link_status.closed();
                match end {
                    SessionEnd::Shutdown => return,
                    SessionEnd::Reconnect => {
                        backoff.reset();
                        log::info!("reconnecting with the new token");
                    }
                    other if opened.elapsed() >= agent.timing.min_stable_session => {
                        backoff.reset();
                        log::info!("disconnected from the Hub ({other:?}); reconnecting");
                    }
                    other => {
                        // The Go agent reconnects at once here, so a Hub that
                        // accepts and closes every socket gets a tight loop of
                        // handshakes. A short session counts as a failure.
                        let duration = backoff.transient();
                        log::warn!(
                            "the connection to the Hub ended after {:?} ({other:?}); retrying in {duration:?}",
                            opened.elapsed()
                        );
                        if !wait(duration, &mut shutdown).await {
                            return;
                        }
                    }
                }
            }
            Err(error) => {
                let kind = if error.is_auth() {
                    FailureKind::Auth
                } else {
                    FailureKind::Transient
                };
                agent.link_status.failed(kind, error.reason());
                if let Some(duration) = after_failure(agent, &mut backoff, &error).await
                    && !wait(duration, &mut shutdown).await
                {
                    return;
                }
            }
        }
    }
}
