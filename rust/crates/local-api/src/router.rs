//! One request to one response, as the Go agent's local server answers:
//! the bearer check of `servicehttp.BearerAuth` (the three probes stay
//! open), then Go's `ServeMux` (any method, exact paths, a redirect for a
//! path that is not clean, `404 page not found` otherwise), then the
//! handlers of `runtime.go` and `servicehttp.go`.

use std::sync::Arc;
use std::time::SystemTime;

use http::header::{AUTHORIZATION, CONTENT_TYPE, ETAG, HOST, IF_NONE_MATCH, LOCATION};
use http::{HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::Full;
use hyper::body::Bytes;
use labtether_agent_config::Secret;

use crate::Source;
use crate::body::{self, LocalFacts, Value};
use crate::gotime::GoTime;
use crate::metrics;

const JSON: &str = "application/json";
const TEXT: &str = "text/plain; charset=utf-8";
const PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";

pub type Reply = Response<Full<Bytes>>;

/// What every request needs, fixed for one listener.
pub struct Router {
    pub name: String,
    /// `None` when the API needs no token.
    pub token: Option<Secret>,
    pub local: LocalFacts,
    pub app_version: String,
    /// When this listener started (Go's `/version` `started_at`).
    pub listening_since: SystemTime,
    pub source: Arc<dyn Source>,
}

fn reply(status: StatusCode, content_type: Option<&'static str>, text: String) -> Reply {
    let mut response = Response::new(Full::new(Bytes::from(text)));
    *response.status_mut() = status;
    if let Some(value) = content_type {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(value));
    }
    response
}

fn json(status: StatusCode, text: String) -> Reply {
    reply(status, Some(JSON), text)
}

/// Go's `http.Error`: plain text with `nosniff`.
fn plain_error(status: StatusCode, text: &str) -> Reply {
    let mut response = reply(status, Some(TEXT), format!("{text}\n"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// What Go's server answers before any handler for a request it refuses.
fn bad_request(detail: &str) -> Reply {
    let mut response = reply(
        StatusCode::BAD_REQUEST,
        Some(TEXT),
        format!("400 Bad Request{detail}"),
    );
    response
        .headers_mut()
        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// The request path with `%XX` decoded (Go's `URL.Path`); `None` for a
/// malformed escape, which Go's server refuses.
fn decode_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Go's `cleanPath` (`path.Clean` keeping a trailing slash).
fn clean_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut clean = format!("/{}", parts.join("/"));
    if path.ends_with('/') && clean != "/" {
        clean.push('/');
    }
    clean
}

/// Go's `http.Redirect` with 307, as the Go 1.27 `ServeMux` sends it for a
/// path that is not clean (checked against the Go agent on the lab VM).
fn redirect(target: String, method: &http::Method) -> Reply {
    let html = target
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;");
    let get = method == http::Method::GET;
    let head = method == http::Method::HEAD;
    let text = if get {
        format!("<a href=\"{html}\">Temporary Redirect</a>.\n\n")
    } else {
        String::new()
    };
    let content_type = (get || head).then_some("text/html; charset=utf-8");
    let mut response = reply(StatusCode::TEMPORARY_REDIRECT, content_type, text);
    if let Ok(value) = HeaderValue::from_str(&target) {
        response.headers_mut().insert(LOCATION, value);
    }
    response
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Go's `BearerAuthProvider` check; `Some` is the refusal.
fn refuse(token: &Secret, header: Option<&HeaderValue>) -> Option<Reply> {
    let header = header
        .map(HeaderValue::as_bytes)
        .unwrap_or_default()
        .trim_ascii();
    let Some(provided) = header.strip_prefix(b"Bearer ") else {
        return Some(json(
            StatusCode::UNAUTHORIZED,
            body::error("missing bearer token"),
        ));
    };
    if constant_time_eq(provided.trim_ascii(), token.expose().as_bytes()) {
        None
    } else {
        Some(json(
            StatusCode::UNAUTHORIZED,
            body::error("invalid bearer token"),
        ))
    }
}

impl Router {
    /// Answers one request. The body is never read; no page needs one.
    pub fn handle<B>(&self, request: &Request<B>) -> Reply {
        if request.version() == Version::HTTP_11 && !request.headers().contains_key(HOST) {
            return bad_request(": missing required Host header");
        }
        let Some(path) = decode_path(request.uri().path()) else {
            return bad_request("");
        };
        let probe = matches!(path.as_str(), "/healthz" | "/readyz" | "/version");
        if let Some(token) = &self.token
            && !probe
            && let Some(refusal) = refuse(token, request.headers().get(AUTHORIZATION))
        {
            return refusal;
        }
        let clean = clean_path(&path);
        if clean != path {
            let target = match request.uri().query() {
                Some(query) => format!("{clean}?{query}"),
                None => clean,
            };
            return redirect(target, request.method());
        }
        match path.as_str() {
            "/healthz" => self.healthz(),
            "/readyz" => json(
                StatusCode::OK,
                body::sorted_map(&mut [
                    ("service", Value::Text(&self.name)),
                    ("ready", Value::Bool(true)),
                ]),
            ),
            "/version" => self.version(),
            "/agent/info" => json(StatusCode::OK, body::agent_info()),
            "/agent/telemetry" => {
                // Go writes the 200 header before encoding; a value it
                // cannot encode leaves the body empty.
                let view = self.source.status_view();
                json(StatusCode::OK, body::telemetry(&view).unwrap_or_default())
            }
            "/agent/status" => self.status(request.headers().get(IF_NONE_MATCH)),
            "/metrics" => reply(
                StatusCode::OK,
                Some(PROMETHEUS),
                metrics::render(&self.source.status_view()),
            ),
            _ => plain_error(StatusCode::NOT_FOUND, "404 page not found"),
        }
    }

    fn healthz(&self) -> Reply {
        let now = GoTime::utc(SystemTime::now()).rfc3339().unwrap_or_default();
        json(
            StatusCode::OK,
            body::sorted_map(&mut [
                ("service", Value::Text(&self.name)),
                ("status", Value::Text("ok")),
                ("timestamp", Value::Text(&now)),
            ]),
        )
    }

    fn version(&self) -> Reply {
        let since = GoTime::utc(self.listening_since)
            .rfc3339()
            .unwrap_or_default();
        json(
            StatusCode::OK,
            body::sorted_map(&mut [
                ("service", Value::Text(&self.name)),
                ("version", Value::Text(&self.app_version)),
                ("started_at", Value::Text(&since)),
            ]),
        )
    }

    fn status(&self, if_none_match: Option<&HeaderValue>) -> Reply {
        let view = self.source.status_view();
        let Ok(status) = body::status(&view, &self.local) else {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                body::error("failed to encode status etag payload"),
            );
        };
        let etag = HeaderValue::from_str(&status.etag).ok();
        let header = if_none_match
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .unwrap_or_default();
        let mut response = if body::etag_matches(&header, &status.etag) {
            reply(StatusCode::NOT_MODIFIED, None, String::new())
        } else {
            json(StatusCode::OK, status.body)
        };
        if let Some(etag) = etag {
            response.headers_mut().insert(ETAG, etag);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::{clean_path, decode_path};

    // Faults: "/agent//status" or "/agent/./status" served without Go's
    // redirect, or "/agent/status/" treated as the status page.
    #[test]
    fn paths_are_cleaned_like_go() {
        for (raw, clean) in [
            ("/agent/status", "/agent/status"),
            ("/agent//status", "/agent/status"),
            ("/agent/./status", "/agent/status"),
            ("/agent/x/../status", "/agent/status"),
            ("/../healthz", "/healthz"),
            ("/healthz/", "/healthz/"),
            ("//", "/"),
            ("", "/"),
        ] {
            assert_eq!(clean_path(raw), clean, "{raw:?}");
        }
        assert_eq!(decode_path("/heal%74hz").as_deref(), Some("/healthz"));
        assert_eq!(decode_path("/bad%zz"), None);
        assert_eq!(decode_path("/cut%2"), None);
    }
}
