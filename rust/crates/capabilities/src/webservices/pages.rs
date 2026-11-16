//! Pages for the recognition probes: Go's `doProbeRequest`, `fetchBody`,
//! `fetchJSON` and `pageContainsMarkerWithResponse` (`fingerprinting.go`).
//! A probe is one GET of the base URL plus a path, with the client Go picks
//! for the URL: for https the one that takes any certificate, then the
//! verified one when no answer came; for http one try. It "answered" (Go's
//! `ok`) when a status came and the first 64 KiB of the page were read.

use std::future::Future;
use std::pin::Pin;

use serde_json::{Map, Value};

use super::health::{Client, Prober};

/// Go's `maxFingerprintBodyBytes`.
pub(crate) const MAX_BODY: usize = 64 * 1024;

/// What one client's GET got: the status, the first `Location` header,
/// and the page, `None` when it could not be read in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page {
    pub status: u16,
    pub location: String,
    pub body: Option<Vec<u8>>,
}

pub(crate) type Fetching<'a> = Pin<Box<dyn Future<Output = Option<Page>> + Send + 'a>>;

/// An answered probe: Go's `(body, status, header, true)`.
#[derive(Debug)]
pub(crate) struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
    pub location: String,
}

/// Go's `doProbeRequest(GET, url)`: `None` when no answer came or the page
/// could not be read (Go's `ok == false`).
pub(crate) async fn get(prober: &dyn Prober, url: &str) -> Option<Answer> {
    let https = url.trim().to_ascii_lowercase().starts_with("https://");
    let first = if https {
        Client::Insecure
    } else {
        Client::Secure
    };
    let page = match prober.fetch(first, url).await {
        Some(page) => page,
        None if https => prober.fetch(Client::Secure, url).await?,
        None => return None,
    };
    Some(Answer {
        status: page.status,
        body: page.body?,
        location: page.location,
    })
}

/// Go's `fetchBody`: the base URL without its trailing `/`, then the path.
pub(crate) async fn fetch_body(prober: &dyn Prober, base: &str, path: &str) -> Option<Answer> {
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    get(prober, &url).await
}

/// Go's `fetchJSON`: the status and the page as a JSON object (`None`
/// when it is not one, or is `null`), when the probe answered.
pub(crate) async fn fetch_json(
    prober: &dyn Prober,
    base: &str,
    path: &str,
) -> Option<(u16, Option<Map<String, Value>>)> {
    let answer = fetch_body(prober, base, path).await?;
    Some((answer.status, json_object(&answer.body)))
}

/// Go's `json.Unmarshal` into a `map[string]any`.
pub(crate) fn json_object(body: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// Go's `pageContainsMarkerWithResponse`: whether the page names the
/// marker, and whether it answered under 500.
pub(crate) async fn page_contains(
    prober: &dyn Prober,
    base: &str,
    path: &str,
    marker: &str,
) -> (bool, bool) {
    match fetch_body(prober, base, path).await {
        Some(answer) if answer.status < 500 => {
            (contains(&answer.body, &marker.to_lowercase()), true)
        }
        _ => (false, false),
    }
}

/// Go's `strings.ToLower`: each character's simple lower case, the first
/// of Rust's full mapping (`İ` is `i`, where Rust's `to_lowercase` gives
/// two characters); bytes that are not UTF-8 count as U+FFFD.
pub(crate) fn go_lower(text: &[u8]) -> String {
    String::from_utf8_lossy(text)
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

/// Whether the lower-cased page holds `marker` (already lower case).
pub(crate) fn contains(body: &[u8], marker: &str) -> bool {
    go_lower(body).contains(marker)
}
