//! Hub address rules, ported from the Go agent's `config_values.go` and
//! `enrollment_state.go`. Plain `ws://` and `http://` are kept only with
//! `LABTETHER_ALLOW_INSECURE_TRANSPORT=true`; otherwise they become secure.

use http::Uri;

/// Which form of Hub address a value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    WebSocket,
    Api,
}

impl UrlKind {
    fn schemes(self) -> (&'static str, &'static str) {
        match self {
            Self::WebSocket => ("wss", "ws"),
            Self::Api => ("https", "http"),
        }
    }

    fn alias(self, scheme: &str) -> Option<&'static str> {
        match (self, scheme) {
            (Self::WebSocket, "https") => Some("wss"),
            (Self::WebSocket, "http") => Some("ws"),
            (Self::Api, "wss") => Some("https"),
            (Self::Api, "ws") => Some("http"),
            _ => None,
        }
    }
}

fn parse(raw: &str) -> Option<Uri> {
    raw.trim().parse::<Uri>().ok()
}

fn authority_has_user(uri: &Uri) -> bool {
    uri.authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
}

fn rebuild(scheme: &str, uri: &Uri, keep_path: bool) -> String {
    let authority = uri.authority().map_or("", |authority| authority.as_str());
    let path = if keep_path {
        uri.path_and_query().map_or("", |pq| pq.as_str())
    } else {
        ""
    };
    format!("{scheme}://{authority}{path}")
}

/// Go's `normalizeWSBaseURL` / `normalizeAPIBaseURL`.
pub fn normalize(raw: &str, kind: UrlKind, allow_insecure: bool) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let Some(uri) = parse(trimmed) else {
        return trimmed.to_owned();
    };
    let Some(scheme) = uri.scheme_str().map(str::to_ascii_lowercase) else {
        return trimmed.to_owned();
    };
    let scheme = kind.alias(&scheme).map_or(scheme, str::to_owned);
    let (secure, insecure) = kind.schemes();
    let chosen = if scheme == secure || (scheme == insecure && !allow_insecure) {
        secure
    } else if scheme == insecure {
        insecure
    } else {
        return trimmed.to_owned();
    };
    rebuild(chosen, &uri, true)
}

/// Go's `apiBaseURLFromWS`: the Hub API origin for a WebSocket address.
pub fn api_from_ws(raw: &str, allow_insecure: bool) -> String {
    let normalized = normalize(raw, UrlKind::WebSocket, allow_insecure);
    let Some(uri) = parse(&normalized).filter(|uri| uri.host().is_some_and(|h| !h.is_empty()))
    else {
        return String::new();
    };
    match uri.scheme_str() {
        Some("wss") => rebuild("https", &uri, false),
        Some("ws") if allow_insecure => rebuild("http", &uri, false),
        Some("ws") => rebuild("https", &uri, false),
        _ => String::new(),
    }
}

/// Go's `wsBaseURLFromAPI`: the WebSocket address for an API origin, keeping
/// the path of a saved WebSocket address (default `/ws/agent`).
pub fn ws_from_api(raw_api: &str, saved_ws: &str, allow_insecure: bool) -> String {
    let api = normalize(raw_api, UrlKind::Api, allow_insecure);
    let Some(uri) = parse(&api).filter(|uri| uri.authority().is_some() && !authority_has_user(uri))
    else {
        return String::new();
    };
    let scheme = match uri.scheme_str() {
        Some("https") => "wss",
        Some("http") if allow_insecure => "ws",
        _ => return String::new(),
    };
    let saved_path = parse(&normalize(saved_ws, UrlKind::WebSocket, allow_insecure))
        .and_then(|saved| saved.path_and_query().map(|pq| pq.path().to_owned()))
        .filter(|path| !path.is_empty() && path != "/");
    let path = saved_path.unwrap_or_else(|| "/ws/agent".to_owned());
    let authority = uri.authority().map_or("", |authority| authority.as_str());
    format!("{scheme}://{authority}{path}")
}

/// Go's `hubOrigin`: lower-case `host:port`, so `ws`/`wss` and `http`/`https`
/// spellings of one address compare equal.
pub fn origin(raw: &str) -> Option<String> {
    let uri = parse(raw)?;
    let host = uri
        .host()
        .filter(|host| !host.is_empty())?
        .to_ascii_lowercase();
    let port = match uri.port_u16() {
        Some(port) => port,
        None => match uri.scheme_str()?.to_ascii_lowercase().as_str() {
            "wss" | "https" => 443,
            "ws" | "http" => 80,
            _ => return None,
        },
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    Some(format!("{host}:{port}"))
}

/// Why a Hub address is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    #[error("the Hub address is missing")]
    Missing,
    #[error("the Hub address is not a valid URL")]
    Invalid,
    #[error("the Hub address must not contain a user name or password")]
    UserInfo,
    #[error("the Hub address uses an insecure or unsupported scheme")]
    Scheme,
}

/// Go's `validatePersistedHubURL` and `validateWebSocketTransportURL`. An
/// empty value is allowed only when `required` is false.
pub fn validate(
    raw: &str,
    kind: UrlKind,
    allow_insecure: bool,
    required: bool,
) -> Result<(), UrlError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return if required {
            Err(UrlError::Missing)
        } else {
            Ok(())
        };
    }
    let uri = parse(trimmed).ok_or(UrlError::Invalid)?;
    if uri.host().is_none_or(str::is_empty) {
        return Err(UrlError::Invalid);
    }
    if authority_has_user(&uri) {
        return Err(UrlError::UserInfo);
    }
    let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
    let (secure, insecure) = kind.schemes();
    if scheme == secure || (scheme == insecure && allow_insecure) {
        Ok(())
    } else {
        Err(UrlError::Scheme)
    }
}

/// The enrollment endpoint: the API address when set, else the WebSocket
/// origin. Go's `enrollWithHubWithIdentityProof`.
pub fn enroll_url(api_url: &str, ws_url: &str, allow_insecure: bool) -> Result<String, UrlError> {
    if !api_url.trim().is_empty() {
        let api = normalize(api_url, UrlKind::Api, allow_insecure);
        return Ok(format!("{}/api/v1/enroll", api.trim_end_matches('/')));
    }
    if ws_url.trim().is_empty() {
        return Err(UrlError::Missing);
    }
    let base = api_from_ws(ws_url, allow_insecure);
    if base.is_empty() {
        return Err(UrlError::Scheme);
    }
    Ok(format!("{base}/api/v1/enroll"))
}

/// `scheme://host:port` for log lines, never the path or anything secret.
pub fn origin_for_log(raw: &str) -> String {
    let Some(uri) = parse(raw) else {
        return "configured hub".to_owned();
    };
    match (uri.scheme_str(), uri.host()) {
        (Some(scheme), Some(host)) if !host.is_empty() => {
            let port = uri
                .port_u16()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            format!("{}://{host}{port}", scheme.to_ascii_lowercase())
        }
        _ => "configured hub".to_owned(),
    }
}
