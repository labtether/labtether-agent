//! The handlers this agent registers, ported from Go's `command_handler.go`
//! (ping), `enrollment_ws_handler.go` (challenge, approved, rejected) and
//! `settings_ws_handler.go` (`config.update`).

use std::sync::atomic::Ordering;

use labtether_agent_config::Secret;
use labtether_agent_config::urls;
use labtether_protocol::{
    AlertNotifyData, ConfigUpdateData, EnrollmentApprovedData, EnrollmentChallengeData,
    EnrollmentProofData, EnrollmentRejectedData, MSG_ALERT_NOTIFY, MSG_CONFIG_APPLIED,
    MSG_CONFIG_UPDATE, MSG_ENROLLMENT_APPROVED, MSG_ENROLLMENT_CHALLENGE, MSG_ENROLLMENT_PROOF,
    MSG_ENROLLMENT_REJECTED, MSG_PING, MSG_PONG, Message,
};

use crate::alerts::Alert;
use crate::credential::{self, CommitOutcome};
use crate::dispatch::{Context, Flow, Registry};
use crate::enroll::MAX_REFUSAL_CHARS;
use crate::features::Features;
use crate::identity::enrollment_proof_payload;
use crate::link_status::{TOKEN_PERSISTENCE_FAILED, printable_one_line};
use crate::state::{valid_asset_id, valid_issued_token};

/// The registry with `core`'s handlers and the features' request handlers.
pub fn registry(features: &Features) -> Registry {
    let mut registry = Registry::new();
    for (kind, work) in features.work() {
        registry.register_work(kind, work.clone());
    }
    registry.register(MSG_PING, ping);
    registry.register(MSG_ENROLLMENT_CHALLENGE, enrollment_challenge);
    registry.register(MSG_ENROLLMENT_APPROVED, enrollment_approved);
    registry.register(MSG_ENROLLMENT_REJECTED, enrollment_rejected);
    registry.register(MSG_CONFIG_UPDATE, config_update);
    registry.register(MSG_ALERT_NOTIFY, alert_notify);
    registry
}

/// Go's `handleAlertNotify`: keeps the alert for the local status page.
fn alert_notify(message: &Message, context: &Context<'_>) -> Flow {
    let Ok(data) = message.decode::<AlertNotifyData>() else {
        log::warn!("invalid alert.notify");
        return Flow::Continue;
    };
    log::info!(
        "alert {} [{}] {}: {}",
        data.id,
        data.severity,
        data.state,
        data.title
    );
    context.agent.alerts.push(Alert::from(data));
    Flow::Continue
}

/// Go's `configUpdateValue`: the value, or "unchanged" when not sent.
fn shown<T: std::fmt::Display>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map_or_else(|| "unchanged".to_owned(), ToString::to_string)
}

/// Applies the Hub's intervals and replies with the ones now in use. The
/// log level in the message is logged only, as in Go.
fn config_update(message: &Message, context: &Context<'_>) -> Flow {
    let Ok(update) = message.decode::<ConfigUpdateData>() else {
        log::warn!("invalid config update");
        return Flow::Continue;
    };
    log::info!(
        "received config update: collect={} heartbeat={} loglevel={}",
        shown(&update.collect_interval_sec),
        shown(&update.heartbeat_interval_sec),
        shown(&update.log_level)
    );
    let applied = context.agent.intervals.apply(&update);
    let sent = Message::with_data(MSG_CONFIG_APPLIED, "", &applied)
        .map_err(|_| crate::outbox::SendError::Encode)
        .and_then(|reply| context.outbox.send(&reply));
    if let Err(error) = sent {
        log::warn!("config.applied not sent: {error}");
    }
    Flow::Continue
}

fn ping(_: &Message, context: &Context<'_>) -> Flow {
    if let Err(error) = context.outbox.send(&Message::bare(MSG_PONG, "")) {
        log::debug!("pong not sent: {error}");
    }
    Flow::Continue
}

fn enrollment_challenge(message: &Message, context: &Context<'_>) -> Flow {
    let Ok(challenge) = message.decode::<EnrollmentChallengeData>() else {
        log::warn!("invalid enrollment.challenge payload");
        return Flow::Continue;
    };
    let nonce = challenge.nonce.trim();
    let connection_id = challenge.connection_id.trim();
    if nonce.is_empty() || connection_id.is_empty() {
        log::warn!("enrollment.challenge is missing nonce or connection_id");
        return Flow::Continue;
    }
    let device = &context.agent.device;
    let payload = enrollment_proof_payload(connection_id, nonce, &device.fingerprint);
    let proof = EnrollmentProofData {
        connection_id: connection_id.to_owned(),
        nonce: nonce.to_owned(),
        key_algorithm: device.key_algorithm().to_owned(),
        public_key: device.public_key_base64.clone(),
        fingerprint: device.fingerprint.clone(),
        signature: device.sign_base64(&payload),
    };
    let sent = Message::with_data(MSG_ENROLLMENT_PROOF, "", &proof)
        .map_err(|_| crate::outbox::SendError::Encode)
        .and_then(|message| context.outbox.send(&message));
    match sent {
        Ok(()) => log::info!("enrollment proof sent for connection {connection_id}"),
        Err(error) => log::warn!("enrollment proof not sent: {error}"),
    }
    Flow::Continue
}

fn enrollment_approved(message: &Message, context: &Context<'_>) -> Flow {
    let Ok(approved) = message.decode::<EnrollmentApprovedData>() else {
        log::warn!("invalid enrollment.approved payload");
        return Flow::Continue;
    };
    let token = approved.token.trim();
    let asset_id = approved.asset_id.trim();
    let Some(token) = Secret::new(token).filter(|token| valid_issued_token(token.expose())) else {
        log::warn!("enrollment.approved has no valid token; ignored");
        return Flow::Continue;
    };
    if !valid_asset_id(asset_id) {
        log::warn!("enrollment.approved has an invalid asset ID; ignored");
        return Flow::Continue;
    }
    log::info!("enrollment approved as {asset_id}");
    let agent = context.agent;
    let insecure = agent.settings.allow_insecure_transport;
    let mut next = agent.identity.snapshot();
    let api = urls::api_from_ws(&next.ws_url, insecure);
    if !api.is_empty() {
        next.api_url = api;
    }
    next.token = Some(token);
    next.asset_id = asset_id.to_owned();
    // The Hub places an approved pending device in no group.
    next.group_id = String::new();
    next.group_known = true;
    agent.identity.replace(next.clone());
    agent.rejected.store(false, Ordering::Relaxed);
    let outcome = credential::commit(&agent.files, &next, Vec::new());
    // Go sets the warning (or clears it) and clears the start-up refusal
    // of the one-use token; the Hub's words stay until a working token.
    agent
        .link_status
        .set_persistence(if outcome == CommitOutcome::MemoryOnly {
            TOKEN_PERSISTENCE_FAILED
        } else {
            ""
        });
    agent.link_status.set_credential_rejected(false);
    Flow::Reconnect
}

fn enrollment_rejected(message: &Message, context: &Context<'_>) -> Flow {
    let Ok(rejected) = message.decode::<EnrollmentRejectedData>() else {
        log::warn!("invalid enrollment.rejected payload");
        return Flow::Continue;
    };
    // Go keeps the trimmed reason as sent; the status contract allows one
    // printable line of at most 300 characters, so it is cut to that.
    let reason = printable_one_line(&rejected.reason, MAX_REFUSAL_CHARS);
    let reason = if reason.is_empty() {
        "An admin rejected this device in LabTether.".to_owned()
    } else {
        reason
    };
    context.agent.rejected.store(true, Ordering::Relaxed);
    context.agent.link_status.set_refusal(&reason);
    log::warn!(
        "LabTether refused the enrollment: {reason} The agent waits for an enrollment token from Devices, Add device."
    );
    Flow::Continue
}
