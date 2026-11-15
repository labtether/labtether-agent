//! Opening the WebSocket to the Hub, ported from Go's `connectWithResponse`:
//! the headers sent on connect, the 16 MiB message limit, and the Hub's
//! token-bound asset ID in `X-LabTether-Asset-ID`.

use http::{HeaderValue, StatusCode, Uri};
use labtether_agent_config::urls::{self, UrlError, UrlKind};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Error as WsError};

use crate::agent::Agent;
use crate::credential::HubIdentity;
use crate::net::{self, DialError, Endpoint, HubStream};
use crate::state::{EnrollmentState, valid_asset_id};

/// Largest message accepted from the Hub (Go: 16 MiB).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Why a connection attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid Hub address: {0}")]
    Address(#[from] UrlError),
    #[error("{0}")]
    Dial(#[from] DialError),
    #[error("the Hub answered HTTP {0}")]
    Status(StatusCode),
    #[error("WebSocket handshake failed: {0}")]
    Handshake(WsError),
    #[error("no answer from the Hub within the handshake time")]
    Timeout,
    #[error("the Hub returned an invalid asset ID")]
    InvalidAssetId,
}

impl ConnectError {
    /// The Hub refused the credential (401 or 403).
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Status(status) if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN)
    }

    /// The Hub's certificate failed the trust check.
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Dial(DialError::Untrusted(_)))
    }
}

/// An open socket and whether it is a pending-enrollment socket.
pub struct Connection {
    pub stream: WebSocketStream<HubStream>,
    pub pending_enrollment: bool,
}

fn header(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

/// The upgrade request with Go's headers.
fn request(
    agent: &Agent,
    identity: &HubIdentity,
    uri: &Uri,
) -> Result<http::Request<()>, ConnectError> {
    let mut request = uri
        .clone()
        .into_client_request()
        .map_err(ConnectError::Handshake)?;
    let headers = request.headers_mut();
    let mut set = |name: &'static str, value: &str| {
        if let Some(value) = header(value) {
            headers.insert(name, value);
        }
    };
    match &identity.token {
        Some(token) => set("authorization", &format!("Bearer {}", token.expose())),
        None => {
            set("x-request-enrollment", "true");
            set("x-hostname", &agent.settings.hostname);
            set("x-device-fingerprint", &agent.device.fingerprint);
            set("x-device-key-alg", agent.device.key_algorithm());
            set("x-device-public-key", &agent.device.public_key_base64);
        }
    }
    set("x-asset-id", &identity.asset_id);
    set("x-platform", "linux");
    if !agent.settings.version.trim().is_empty() {
        set("x-agent-version", agent.settings.version.trim());
    }
    Ok(request)
}

async fn open(
    agent: &Agent,
    identity: &HubIdentity,
    uri: &Uri,
) -> Result<(WebSocketStream<HubStream>, http::HeaderMap), ConnectError> {
    let endpoint = Endpoint::from_uri(uri)?;
    let request = request(agent, identity, uri)?;
    let stream = net::dial(&endpoint, &agent.tls).await?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    match tokio_tungstenite::client_async_with_config(request, stream, Some(config)).await {
        Ok((socket, response)) => Ok((socket, response.headers().clone())),
        Err(tungstenite::Error::Http(response)) => Err(ConnectError::Status(response.status())),
        Err(error) => Err(ConnectError::Handshake(error)),
    }
}

/// Opens one connection with the current identity.
pub async fn connect(agent: &Agent) -> Result<Connection, ConnectError> {
    let identity = agent.identity.snapshot();
    let insecure = agent.settings.allow_insecure_transport;
    urls::validate(&identity.ws_url, UrlKind::WebSocket, insecure, true)?;
    let uri: Uri = identity.ws_url.parse().map_err(|_| UrlError::Invalid)?;
    let (stream, headers) =
        tokio::time::timeout(agent.timing.handshake_timeout, open(agent, &identity, &uri))
            .await
            .map_err(|_| ConnectError::Timeout)??;

    let canonical = headers
        .get("x-labtether-asset-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if identity.token.is_some() && !canonical.is_empty() {
        if !valid_asset_id(canonical) {
            return Err(ConnectError::InvalidAssetId);
        }
        if agent.identity.adopt_asset(canonical) {
            let adopted = agent.identity.snapshot();
            let state = EnrollmentState {
                asset_id: adopted.asset_id.clone(),
                group_id: adopted.group_known.then(|| adopted.group_id.clone()),
                hub_ws_url: adopted.ws_url.clone(),
                hub_api_url: adopted.api_url.clone(),
                token_origins: agent.files.saved_origins(),
                ..EnrollmentState::default()
            };
            if let Err(error) = agent.files.save_state(state) {
                log::warn!("could not save the Hub's asset ID: {error}");
            }
        }
    }
    let pending_enrollment = identity.token.is_none();
    let origin = urls::origin_for_log(&identity.ws_url);
    if pending_enrollment {
        log::info!("pending enrollment socket connected to {origin}");
    } else {
        log::info!("connected to {origin}");
    }
    Ok(Connection {
        stream,
        pending_enrollment,
    })
}
