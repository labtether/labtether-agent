//! Token enrollment over HTTP (`POST /api/v1/enroll`), ported from Go's
//! `enroll.go` and `enroll_refusal.go`.

use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use labtether_agent_config::Secret;
use labtether_agent_config::urls::{self, UrlKind};
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};

use crate::identity::{DeviceIdentity, ProofVersion, token_proof_payload};
use crate::link_status::printable_one_line;
use crate::post::{self, HttpError};
use crate::state::{valid_asset_id, valid_issued_token};

const ENROLL_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_REFUSAL_BYTES: usize = 4096;
/// Longest Hub refusal kept (Go's `maxEnrollmentRefusalRunes`).
pub const MAX_REFUSAL_CHARS: usize = 300;

#[derive(Serialize)]
struct EnrollRequest<'a> {
    enrollment_token: &'a str,
    hostname: &'a str,
    platform: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    group_id: &'a str,
    device_key_algorithm: &'a str,
    device_public_key: &'a str,
    device_fingerprint: &'a str,
    device_signature: String,
    device_proof_version: &'a str,
}

#[derive(Deserialize)]
struct RawResponse {
    #[serde(default)]
    agent_token: String,
    #[serde(default)]
    asset_id: String,
    /// Present (maybe empty) on current Hubs; absent on older ones.
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    hub_ws_url: String,
    #[serde(default)]
    hub_api_url: String,
    #[serde(default)]
    ca_cert_pem: String,
}

/// A checked enrollment answer.
#[derive(Debug)]
pub struct Enrolled {
    pub token: Secret,
    pub asset_id: String,
    pub group_id: Option<String>,
    pub hub_ws_url: String,
    pub hub_api_url: String,
    pub ca_cert_pem: String,
}

/// Why enrollment failed.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("enrollment needs LABTETHER_WS_URL or LABTETHER_API_BASE_URL")]
    NoAddress,
    #[error("{0}")]
    Http(#[from] HttpError),
    /// The Hub answered with an error status; `message` is its own words.
    #[error("{}", refusal_text(*.status, .message))]
    Refused { status: StatusCode, message: String },
    #[error("the enrollment answer is not valid: {0}")]
    BadAnswer(&'static str),
}

fn refusal_text(status: StatusCode, message: &str) -> String {
    if message.is_empty() {
        format!("enroll returned status {}", status.as_u16())
    } else {
        format!(
            "LabTether refused the enrollment (HTTP {}): {message}",
            status.as_u16()
        )
    }
}

impl EnrollError {
    /// Go's `isEnrollmentCredentialRejected`: the token itself was refused.
    pub fn is_token_rejected(&self) -> bool {
        matches!(self, Self::Refused { status, .. } if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN)
    }

    /// Go's `enrollmentRefusalMessage`: the Hub's own words, when it sent
    /// any.
    pub fn hub_words(&self) -> Option<&str> {
        match self {
            Self::Refused { message, .. } if !message.is_empty() => Some(message),
            _ => None,
        }
    }
}

/// What the request proves and where it goes.
pub struct EnrollRequestInput<'a> {
    pub api_url: &'a str,
    pub ws_url: &'a str,
    pub allow_insecure: bool,
    pub token: &'a Secret,
    /// The name the Hub turns into the asset ID (v1) or the Hub's asset ID (v2).
    pub subject: &'a str,
    pub group_id: &'a str,
    pub proof: ProofVersion,
}

/// Go's `selectEnrollmentHostname`: the configured asset ID when valid, else
/// a printable system host name, else `labtether-agent`.
pub fn enrollment_hostname(asset_id: &str, system_hostname: &str) -> String {
    let asset_id = asset_id.trim();
    if valid_asset_id(asset_id) {
        return asset_id.to_owned();
    }
    let host = system_hostname.trim();
    if !host.is_empty() && host.len() <= 253 && !host.chars().any(char::is_control) {
        return host.to_owned();
    }
    "labtether-agent".to_owned()
}

/// Sends one enrollment request and checks the answer.
pub async fn enroll(
    input: &EnrollRequestInput<'_>,
    device: &DeviceIdentity,
    tls: &Arc<ClientConfig>,
) -> Result<Enrolled, EnrollError> {
    let url = urls::enroll_url(input.api_url, input.ws_url, input.allow_insecure)
        .map_err(|_| EnrollError::NoAddress)?;
    let payload = token_proof_payload(
        input.proof,
        input.subject,
        input.token.expose(),
        &device.fingerprint,
    );
    let request = EnrollRequest {
        enrollment_token: input.token.expose(),
        hostname: input.subject,
        platform: labtether_agent_platform::PLATFORM,
        group_id: input.group_id,
        device_key_algorithm: device.key_algorithm(),
        device_public_key: &device.public_key_base64,
        device_fingerprint: &device.fingerprint,
        device_signature: device.sign_base64(&payload),
        device_proof_version: input.proof.as_str(),
    };
    let body = serde_json::to_vec(&request).map_err(|_| EnrollError::BadAnswer("request"))?;
    let answer = post::post_json(&url, body, tls, ENROLL_TIMEOUT, MAX_RESPONSE_BYTES).await?;
    if answer.status != StatusCode::OK {
        let limit = answer.body.len().min(MAX_REFUSAL_BYTES);
        return Err(EnrollError::Refused {
            status: answer.status,
            message: hub_message(&answer.body[..limit]),
        });
    }
    let raw: RawResponse =
        serde_json::from_slice(&answer.body).map_err(|_| EnrollError::BadAnswer("not JSON"))?;
    check_answer(raw, input.allow_insecure)
}

fn check_answer(raw: RawResponse, allow_insecure: bool) -> Result<Enrolled, EnrollError> {
    let token = raw.agent_token.trim();
    if !valid_issued_token(token) {
        return Err(EnrollError::BadAnswer("agent_token"));
    }
    let asset_id = raw.asset_id.trim().to_owned();
    if !valid_asset_id(&asset_id) {
        return Err(EnrollError::BadAnswer("asset_id"));
    }
    let hub_ws_url = urls::normalize(&raw.hub_ws_url, UrlKind::WebSocket, allow_insecure);
    let hub_api_url = urls::normalize(&raw.hub_api_url, UrlKind::Api, allow_insecure);
    urls::validate(&hub_ws_url, UrlKind::WebSocket, allow_insecure, false)
        .map_err(|_| EnrollError::BadAnswer("hub_ws_url"))?;
    urls::validate(&hub_api_url, UrlKind::Api, allow_insecure, false)
        .map_err(|_| EnrollError::BadAnswer("hub_api_url"))?;
    Ok(Enrolled {
        token: Secret::new(token).ok_or(EnrollError::BadAnswer("agent_token"))?,
        asset_id,
        group_id: raw.group_id.map(|group| group.trim().to_owned()),
        hub_ws_url,
        hub_api_url,
        ca_cert_pem: raw.ca_cert_pem,
    })
}

/// Go's `newEnrollmentRefusal`: the Hub's `message` (or `error`) as one line
/// of printable text, at most 300 characters.
fn hub_message(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Refusal {
        #[serde(default)]
        error: String,
        #[serde(default)]
        message: String,
    }
    let Ok(refusal) = serde_json::from_slice::<Refusal>(body) else {
        return String::new();
    };
    let text = if refusal.message.trim().is_empty() {
        refusal.error
    } else {
        refusal.message
    };
    printable_one_line(&text, MAX_REFUSAL_CHARS)
}
