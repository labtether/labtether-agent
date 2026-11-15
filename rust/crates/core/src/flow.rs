//! What happens around an enrollment call: at start with a staged one-use
//! token (Go's `resolveTokenWithIdentity`), and after repeated refused
//! credentials (Go's `reEnrollAgainstActiveHub`).

use std::path::PathBuf;
use std::sync::Arc;

use labtether_agent_config::urls;
use labtether_agent_config::{EnrollmentToken, Settings};
use labtether_protocol::canonical_enrollment_asset_id;
use rustls::ClientConfig;

use crate::agent::Agent;
use crate::credential::{self, HubIdentity};
use crate::enroll::{self, EnrollError, EnrollRequestInput, Enrolled, enrollment_hostname};
use crate::fsutil::{self, PUBLIC};
use crate::identity::{DeviceIdentity, ProofVersion};
use crate::state::{StateFiles, merge_origins};
use crate::tls;

/// The result of enrollment at start.
#[derive(Debug)]
pub struct StartEnrollment {
    pub identity: HubIdentity,
    /// The Hub's CA, saved as `ca.crt`, to trust from now on.
    pub saved_ca: Option<PathBuf>,
}

/// Enrolls with the staged token and commits the answer.
pub async fn enroll_at_start(
    settings: &Settings,
    files: &StateFiles,
    device: &DeviceIdentity,
    tls_config: &Arc<ClientConfig>,
    configured: &HubIdentity,
    staged: &EnrollmentToken,
) -> Result<StartEnrollment, EnrollError> {
    let insecure = settings.allow_insecure_transport;
    if configured.ws_url.is_empty() && settings.api_url.is_empty() {
        return Err(EnrollError::NoAddress);
    }
    log::info!("enrolling with the Hub");
    let hostname = enrollment_hostname(&settings.asset_id, &settings.hostname);
    let input = EnrollRequestInput {
        api_url: &settings.api_url,
        ws_url: &configured.ws_url,
        allow_insecure: insecure,
        token: &staged.token,
        subject: &hostname,
        group_id: &settings.group_id,
        proof: ProofVersion::V1,
    };
    let enrolled = enroll::enroll(&input, device, tls_config).await?;

    let mut identity = configured.clone();
    identity.token = Some(enrolled.token.clone());
    identity.asset_id = enrolled.asset_id.clone();
    if let Some(group) = &enrolled.group_id {
        identity.group_id = group.clone();
        identity.group_known = true;
    }
    // Keep the address that just reached the Hub; the Hub may name one this
    // host cannot reach.
    if configured.ws_url.is_empty() {
        if !enrolled.hub_ws_url.is_empty() {
            identity.ws_url = enrolled.hub_ws_url.clone();
        }
        if !enrolled.hub_api_url.is_empty() {
            identity.api_url = enrolled.hub_api_url.clone();
        }
    } else if identity.api_url.is_empty() {
        identity.api_url = urls::api_from_ws(&identity.ws_url, insecure);
    }
    let origins = merge_origins(
        &[],
        &[
            &configured.ws_url,
            &settings.api_url,
            &enrolled.hub_ws_url,
            &enrolled.hub_api_url,
        ],
    );
    credential::commit(files, &identity, origins);
    if let Err(error) = files.discard_used_enrollment_token(staged) {
        log::error!("cleanup of the used enrollment token failed: {error}");
    }
    let saved_ca = save_hub_ca(settings, files, &enrolled);
    log::info!("enrolled as {}", identity.asset_id);
    Ok(StartEnrollment { identity, saved_ca })
}

/// Go keeps a CA the user configured (for a TLS proxy in front of the Hub),
/// and with CA-only on never replaces the pinned CA from an answer.
fn save_hub_ca(settings: &Settings, files: &StateFiles, enrolled: &Enrolled) -> Option<PathBuf> {
    if enrolled.ca_cert_pem.is_empty() || settings.tls.ca_only {
        return None;
    }
    if settings
        .tls
        .ca_file
        .as_deref()
        .is_some_and(|configured| configured != files.ca)
    {
        return None;
    }
    if !tls::is_ca_certificate_pem(&enrolled.ca_cert_pem) {
        log::warn!("the Hub returned a CA certificate that is not a CA; it is not saved");
        return None;
    }
    match fsutil::write_atomic(&files.ca, enrolled.ca_cert_pem.as_bytes(), PUBLIC) {
        Ok(()) => {
            log::info!("saved the Hub CA certificate to {}", files.ca.display());
            Some(files.ca.clone())
        }
        Err(error) => {
            log::warn!(
                "could not save the Hub CA to {}: {error}",
                files.ca.display()
            );
            None
        }
    }
}

/// Re-enrolls against the Hub address that just refused the token, with the
/// v2 proof bound to the Hub's asset ID. On success the new identity is in
/// use and the one-use token is spent.
pub async fn re_enroll(agent: &Agent, staged: &EnrollmentToken) -> Result<(), EnrollError> {
    let insecure = agent.settings.allow_insecure_transport;
    let current = agent.identity.snapshot();
    let asset_id = canonical_enrollment_asset_id(&current.asset_id);
    if current.ws_url.is_empty() || asset_id.is_empty() {
        return Err(EnrollError::NoAddress);
    }
    let input = EnrollRequestInput {
        api_url: "",
        ws_url: &current.ws_url,
        allow_insecure: insecure,
        token: &staged.token,
        subject: &asset_id,
        group_id: &current.group_id,
        proof: ProofVersion::V2,
    };
    let enrolled = enroll::enroll(&input, &agent.device, &agent.tls).await?;
    let mut next = current.clone();
    next.token = Some(enrolled.token.clone());
    next.asset_id = enrolled.asset_id.clone();
    next.api_url = urls::api_from_ws(&current.ws_url, insecure);
    if let Some(group) = &enrolled.group_id {
        next.group_id = group.clone();
        next.group_known = true;
    }
    agent.identity.replace(next.clone());
    let origins = merge_origins(&[], &[&enrolled.hub_ws_url, &enrolled.hub_api_url]);
    credential::commit(&agent.files, &next, origins);
    if let Err(error) = agent.files.discard_used_enrollment_token(staged) {
        log::error!("cleanup of the used re-enrollment token failed: {error}");
    }
    Ok(())
}
