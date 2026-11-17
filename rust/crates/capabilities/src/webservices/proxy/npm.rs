//! Nginx Proxy Manager: Go's `NPMProvider` (`proxy/npm.go`). Found as a
//! `jc21/nginx-proxy-manager` image with its admin port 81 published, at
//! `https://localhost:<published port>` (http only when
//! `LABTETHER_ALLOW_INSECURE_TRANSPORT` is `true`, `1` or `yes`), or at
//! `LABTETHER_NPM_URL`. With `LABTETHER_NPM_EMAIL` and `_PASSWORD` set it
//! logs in (`POST /api/tokens`, the token kept an hour) and reads
//! `GET /api/nginx/proxy-hosts`: one route per domain of each enabled
//! host, to `<scheme>://<host>:<port>`, TLS when SSL is forced. Every
//! request passes Go's outbound rules, so a local NPM is refused unless
//! loopback is allowed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use labtether_agent_config::Secret;
use serde::Deserialize;

use super::api::{ApiRequest, ProxyApi, check_outbound, send};
use super::outbound::Outbound;
use super::{Route, decode_first, find_host_port, normalize_image, nullable};
use crate::docker::raw::Container;
use crate::webservices::gourl;

const ADMIN_PORT: i64 = 81;
/// Go keeps a token an hour (NPM's last a day).
const TOKEN_LIFE: Duration = Duration::from_secs(3600);

/// The token and when Go stops using it.
pub(crate) type Token = Mutex<Option<(String, Instant)>>;

/// Go's `DetectAndConnect`. `http` is Go's `allowInsecureTransportOptIn`.
pub(crate) fn detect(containers: &[Container], manual: &str, http: bool) -> Option<String> {
    if !manual.is_empty() {
        return Some(manual.to_owned());
    }
    for c in containers {
        if normalize_image(&c.image) != "jc21/nginx-proxy-manager" {
            continue;
        }
        let port = find_host_port(&c.ports, ADMIN_PORT);
        if port == 0 {
            log::info!(
                "webservices: NPM container {} has no published admin port {ADMIN_PORT}; trying the next one",
                c.id
            );
            continue;
        }
        let scheme = if http { "http" } else { "https" };
        let url = format!("{scheme}://localhost:{port}");
        log::info!("webservices: NPM found at {url} (container {})", c.id);
        return Some(url);
    }
    None
}

#[derive(Debug, Deserialize)]
struct TokenAnswer {
    #[serde(default, deserialize_with = "nullable")]
    token: String,
    /// Read as Go reads it: not a string is an error.
    #[serde(rename = "expires", default, deserialize_with = "nullable")]
    _expires: String,
}

#[derive(Debug, Deserialize)]
struct ProxyHost {
    #[serde(default, deserialize_with = "nullable")]
    id: i64,
    #[serde(default, deserialize_with = "nullable")]
    domain_names: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    forward_host: String,
    #[serde(default, deserialize_with = "nullable")]
    forward_port: i64,
    #[serde(default, deserialize_with = "nullable")]
    forward_scheme: String,
    #[serde(default, deserialize_with = "nullable")]
    ssl_forced: bool,
    #[serde(default, deserialize_with = "nullable")]
    enabled: bool,
}

/// Go's `encoding/json` string: `<`, `>`, `&`, U+2028 and U+2029 escaped
/// too.
pub(crate) fn go_json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go's `npmEndpointURL`: the API path after the base URL's own path.
pub(crate) fn endpoint(base: &str, path: &str) -> Result<String, String> {
    let trimmed = base.trim();
    if trimmed.is_empty() {
        return Err("NPM API url is required".into());
    }
    let invalid = || format!("invalid NPM API url {base:?}");
    let mut url = gourl::parse(trimmed).ok_or_else(invalid)?;
    if url.host.trim().is_empty() {
        return Err(invalid());
    }
    let mut full = url.path.clone();
    while full.last() == Some(&b'/') {
        full.pop();
    }
    full.extend_from_slice(path.as_bytes());
    url.set_plain_path(full);
    Ok(url.text())
}

/// One request through the outbound rules (Go's
/// `NewOutboundRequestWithContext` and `DoOutboundRequest`).
async fn outbound_send(
    api: &dyn ProxyApi,
    rules: &Outbound,
    request: ApiRequest,
    what: &str,
) -> Result<super::api::ApiResponse, String> {
    check_outbound(api, rules, &request.url)
        .await
        .map_err(|e| format!("build {what}: {e}"))?;
    send(api, request, Some(rules))
        .await
        .map_err(|e| format!("{what}: {e}"))
}

async fn authenticate(
    api: &dyn ProxyApi,
    rules: &Outbound,
    base: &str,
    email: &str,
    password: &Secret,
) -> Result<String, String> {
    let body = format!(
        "{{\"identity\":{},\"secret\":{}}}",
        go_json_string(email),
        go_json_string(password.expose())
    );
    let request = ApiRequest {
        json: Some(body.into_bytes()),
        method: "POST",
        ..ApiRequest::get(endpoint(base, "/api/tokens")?, None)
    };
    let response = outbound_send(api, rules, request, "token request").await?;
    if response.status != 200 {
        return Err(format!("token endpoint returned HTTP {}", response.status));
    }
    let answer: TokenAnswer =
        decode_first(&response.body).map_err(|e| format!("decode token response: {e}"))?;
    if answer.token.is_empty() {
        return Err("empty token in response".into());
    }
    Ok(answer.token)
}

/// Go's `FetchRoutes`.
pub(crate) async fn fetch(
    api: &dyn ProxyApi,
    rules: &Outbound,
    base: &str,
    email: &str,
    password: Option<&Secret>,
    token: &Token,
) -> Result<Vec<Route>, String> {
    let password = match password {
        Some(password) if !email.is_empty() => password,
        _ => {
            return Err("NPM credentials not configured (set LABTETHER_NPM_EMAIL and LABTETHER_NPM_PASSWORD)".into());
        }
    };
    let cached = token
        .lock()
        .map_err(|_| "token cache poisoned")?
        .clone()
        .filter(|(_, until)| Instant::now() < *until);
    let bearer = match cached {
        Some((bearer, _)) => bearer,
        None => {
            let fresh = authenticate(api, rules, base, email, password)
                .await
                .map_err(|e| format!("NPM authentication failed: {e}"))?;
            *token.lock().map_err(|_| "token cache poisoned")? =
                Some((fresh.clone(), Instant::now() + TOKEN_LIFE));
            fresh
        }
    };
    let request = ApiRequest::get(
        endpoint(base, "/api/nginx/proxy-hosts")?,
        Some(format!("Bearer {bearer}")),
    );
    let fetched = async {
        let response = outbound_send(api, rules, request, "proxy hosts request").await?;
        if response.status != 200 {
            return Err(format!(
                "proxy hosts endpoint returned HTTP {}",
                response.status
            ));
        }
        decode_first::<Option<Vec<ProxyHost>>>(&response.body)
            .map(Option::unwrap_or_default)
            .map_err(|e| format!("decode proxy hosts: {e}"))
    };
    let hosts = fetched
        .await
        .map_err(|e| format!("NPM proxy hosts fetch failed: {e}"))?;
    let mut routes = Vec::new();
    for host in hosts.iter().filter(|h| h.enabled) {
        let backend_url = format!(
            "{}://{}:{}",
            host.forward_scheme, host.forward_host, host.forward_port
        );
        for domain in &host.domain_names {
            routes.push(Route {
                domain: domain.clone(),
                backend_url: backend_url.clone(),
                tls: host.ssl_forced,
                router_name: format!("npm-host-{}", host.id),
            });
        }
    }
    Ok(routes)
}
