//! Enrollment once the Hub answers, for an agent started while its Hub was
//! down (Go: `enroll_when_reachable.go`). Such an agent used to connect
//! without a token, so the Hub held it as a pending device for an admin to
//! approve and its one-use token was never used. Now the reconnect loop
//! enrolls with the staged token before it would open a socket without one,
//! waiting between tries as after a failed connect. Once the Hub refuses the
//! token or the request, the agent connects as a pending device, as it does
//! when the Hub refuses the token at start.

use std::sync::atomic::Ordering;

use crate::agent::Agent;
use crate::enroll::EnrollError;
use crate::flow;
use crate::link_status::{FailureKind, TOKEN_PERSISTENCE_FAILED};

/// What the reconnect loop does next.
pub(crate) enum LateEnrollment {
    /// Nothing to enroll, or the Hub refused: connect as before.
    Connect,
    /// The token is spent and the issued one is in use: connect with it.
    Enrolled,
    /// The Hub did not answer: wait as after a failed connect, then try again.
    Unanswered(EnrollError),
}

/// Tries the start-up enrollment again while it is armed and no token is in
/// use.
pub(crate) async fn try_enroll(agent: &Agent) -> LateEnrollment {
    let staged = {
        let state = agent.re_enroll_state();
        match &state.token {
            Some(token) if state.at_connect => token.clone(),
            _ => return LateEnrollment::Connect,
        }
    };
    let configured = agent.identity.snapshot();
    if configured.token.is_some() {
        return LateEnrollment::Connect;
    }
    match flow::enroll_at_start(
        &agent.settings,
        &agent.files,
        &agent.device,
        &agent.tls(),
        &configured,
        &staged,
    )
    .await
    {
        Ok(done) => {
            // As at start: the CA the Hub returned is trusted before the
            // issued token is used.
            if let Some(ca_file) = done.saved_ca {
                agent.use_saved_ca(ca_file);
            }
            agent.identity.replace(done.identity);
            {
                let mut state = agent.re_enroll_state();
                state.token = None;
                state.at_connect = false;
            }
            // As after re-enrollment: Go's `updateToken` clears the failure,
            // the refusal and the rejection.
            agent.link_status.set_persistence(if done.memory_only {
                TOKEN_PERSISTENCE_FAILED
            } else {
                ""
            });
            agent.link_status.token_replaced();
            agent.rejected.store(false, Ordering::Relaxed);
            log::info!("enrolled with the enrollment token, connecting");
            LateEnrollment::Enrolled
        }
        Err(error) if error.is_retryable() => {
            agent
                .link_status
                .failed(FailureKind::Transient, error.reason());
            LateEnrollment::Unanswered(error)
        }
        Err(error) => {
            // Never offer a refused token again from here; the token stays
            // for re-enrollment, as when the Hub refuses it at start.
            agent.re_enroll_state().at_connect = false;
            log::error!("enrollment failed: {error}");
            agent
                .link_status
                .set_credential_rejected(error.is_token_rejected());
            if let Some(words) = error.hub_words() {
                agent.link_status.set_refusal(words);
            }
            LateEnrollment::Connect
        }
    }
}
