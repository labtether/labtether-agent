//! Requests to the proxies' APIs, as Go's `http.Client{Timeout: 5s}` sends
//! them: 5 s for the whole exchange, redirects followed as Go's client
//! follows them (at most 10; 301, 302 and 303 turn a POST into a GET
//! without its body and body headers, 307 and 308 keep both; the
//! `Authorization` header dropped once the host changes to one that is not
//! the same name or under it; a `Referer` unless https goes to http). For
//! NPM, Go's outbound rules check every URL and every address connected to.
//!
//! [`ProxyApi`] is one exchange; the tests answer it from tables.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use super::outbound::Outbound;
use crate::webservices::gourl;

/// Go's provider clients' `Timeout`.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REDIRECTS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiRequest {
    pub method: &'static str,
    pub url: String,
    pub authorization: Option<String>,
    /// A JSON body (sent with `Content-Type: application/json`).
    pub json: Option<Vec<u8>>,
    pub referer: Option<String>,
}

impl ApiRequest {
    pub fn get(url: String, authorization: Option<String>) -> Self {
        Self {
            method: "GET",
            url,
            authorization,
            json: None,
            referer: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ApiResponse {
    pub status: u16,
    /// The first `Location` header, empty when none.
    pub location: String,
    pub body: Vec<u8>,
}

pub(crate) type Exchanging<'a> =
    Pin<Box<dyn Future<Output = Result<ApiResponse, String>> + Send + 'a>>;
pub(crate) type Resolving<'a> = Pin<Box<dyn Future<Output = Option<Vec<IpAddr>>> + Send + 'a>>;

/// The proxies' APIs: one request, no redirect followed.
pub(crate) trait ProxyApi: Send + Sync {
    /// Sends `request`; with `rules`, connects only to addresses they
    /// allow (Go's `dialOutboundValidated`, private addresses judged by
    /// the first request's scheme, `private_scheme`).
    fn exchange<'a>(
        &'a self,
        request: &'a ApiRequest,
        rules: Option<(&'a Outbound, &'a str)>,
    ) -> Exchanging<'a>;

    /// Go's resolver look-up of a name for the outbound rules (2 s).
    fn resolve<'a>(&'a self, host: &'a str) -> Resolving<'a>;
}

/// Checks `url` against the outbound rules, looking the name up first
/// when Go would.
pub(crate) async fn check_outbound(
    api: &dyn ProxyApi,
    rules: &Outbound,
    url: &str,
) -> Result<(), String> {
    let resolved = match Outbound::name_to_resolve(url) {
        Some(host) => api.resolve(&host).await,
        None => None,
    };
    rules.check_url(url, resolved.as_deref())
}

/// Go's `isDomainOrSubdomain`.
fn same_or_under(sub: &str, parent: &str) -> bool {
    if sub == parent {
        return true;
    }
    if sub.contains([':', '%']) || !sub.ends_with(parent) {
        return false;
    }
    sub.as_bytes().get(sub.len() - parent.len() - 1) == Some(&b'.')
}

/// One request with Go's client's redirects, within [`TIMEOUT`]. With
/// `rules`, each redirect's URL must pass them too (Go's secure client).
pub(crate) async fn send(
    api: &dyn ProxyApi,
    first: ApiRequest,
    rules: Option<&Outbound>,
) -> Result<ApiResponse, String> {
    match tokio::time::timeout(TIMEOUT, follow(api, first, rules)).await {
        Ok(result) => result,
        Err(_) => Err("Client.Timeout exceeded while awaiting headers".into()),
    }
}

async fn follow(
    api: &dyn ProxyApi,
    first: ApiRequest,
    rules: Option<&Outbound>,
) -> Result<ApiResponse, String> {
    let scheme = gourl::parse(&first.url).map_or_else(String::new, |u| u.scheme);
    let first_url = gourl::parse(&first.url).ok_or("invalid url")?;
    let mut request = first.clone();
    let mut current = first_url.clone();
    let mut strip_auth = false;
    let mut redirects = 0;
    loop {
        if !matches!(current.scheme.as_str(), "http" | "https") {
            return Err(format!("unsupported protocol scheme {:?}", current.scheme));
        }
        let response = api
            .exchange(&request, rules.map(|r| (r, scheme.as_str())))
            .await?;
        let (method, keep_body) = match response.status {
            301..=303 if matches!(request.method, "GET" | "HEAD") => (request.method, false),
            301..=303 => ("GET", false),
            307 | 308 => (request.method, true),
            _ => return Ok(response),
        };
        if response.location.is_empty() {
            return Ok(response);
        }
        let next = gourl::parse(&response.location)
            .map(|reference| current.resolve(&reference))
            .ok_or_else(|| format!("failed to parse Location header {:?}", response.location))?;
        if !strip_auth && first_url.host != next.host {
            let initial = first_url.hostname().to_ascii_lowercase();
            strip_auth = !same_or_under(&next.hostname().to_ascii_lowercase(), &initial);
        }
        let referer = (!(current.scheme == "https" && next.scheme == "http"))
            .then(|| current.text())
            .map(|text| match current.user.as_deref() {
                Some(user) => text.replacen(&format!("{user}@"), "", 1),
                None => text,
            });
        let next_text = next.text();
        if let Some(rules) = rules {
            check_outbound(api, rules, &next_text).await?;
        }
        if redirects >= MAX_REDIRECTS {
            return Err("stopped after 10 redirects".into());
        }
        redirects += 1;
        request = ApiRequest {
            method,
            url: next_text,
            authorization: first.authorization.clone().filter(|_| !strip_auth),
            json: first.json.clone().filter(|_| keep_body),
            referer,
        };
        current = next;
    }
}
