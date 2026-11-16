//! Service URLs as the Go collector writes and reads them: Go's
//! `buildServiceURL`, `formatURLHost`, `portFromURL`, `alternateSchemeURL`
//! and the port tables of `discovery_docker.go`. The URLs this part reads
//! are the ones it writes (`scheme://host:port`, a health path after it),
//! so the parser takes only an `http` or `https` URL with a host.

use std::net::IpAddr;

/// Go's `isLikelyHTTPSPort`: the guess before a probe corrects it.
pub(crate) fn is_likely_https_port(port: i64) -> bool {
    matches!(port, 443 | 7443 | 8006 | 8007 | 8443 | 9443 | 10443)
}

/// Go's `isLikelyWebPort`, the same list as `defaultPortScanCandidates`.
pub(crate) fn is_likely_web_port(port: i64) -> bool {
    matches!(
        port,
        80 | 81
            | 82
            | 88
            | 443
            | 591
            | 593
            | 631
            | 2375
            | 2376
            | 3000
            | 3001
            | 3002
            | 4000
            | 5000
            | 5055
            | 5601
            | 6001
            | 7000
            | 7080
            | 7081
            | 7443
            | 7474
            | 8000
            | 8001
            | 8006
            | 8007
            | 8080
            | 8081
            | 8082
            | 8088
            | 8089
            | 8090
            | 8091
            | 8096
            | 8123
            | 8181
            | 8443
            | 8888
            | 8989
            | 9000
            | 9001
            | 9090
            | 9091
            | 9443
            | 9696
            | 10443
            | 19999
            | 32400
    )
}

/// Go's `formatURLHost`: an IPv6 address in brackets, `localhost` when
/// empty.
pub(crate) fn format_url_host(host: &str) -> String {
    let value = host.trim();
    if value.is_empty() {
        return "localhost".to_owned();
    }
    if value.starts_with('[') && value.ends_with(']') {
        return value.to_owned();
    }
    if value.contains(':') && value.parse::<IpAddr>().is_ok() {
        return format!("[{value}]");
    }
    value.to_owned()
}

/// Go's `buildServiceURL`: https on the usual TLS ports, http elsewhere.
pub(crate) fn build_service_url(host: &str, port: i64) -> String {
    let host = if host.is_empty() { "localhost" } else { host };
    let scheme = if is_likely_https_port(port) {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{}:{port}", format_url_host(host))
}

/// An `http` or `https` URL split as a request needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub https: bool,
    /// The host without brackets, as a connection takes it.
    pub host: String,
    pub port: u16,
    /// `host:port` as written, for the `Host` header (Go's `URL.Host`).
    pub authority: String,
    /// The path and query, `/` when empty.
    pub path: String,
}

impl Target {
    pub fn parse(raw: &str) -> Option<Self> {
        let (scheme, rest) = raw.split_once("://")?;
        let https = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => return None,
        };
        let rest = rest.split('#').next().unwrap_or(rest);
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return None;
        }
        let port = match port {
            "" if https => 443,
            "" => 80,
            digits => parse_port(digits)?,
        };
        let path = match path {
            "" => "/".to_owned(),
            query if query.starts_with('?') => format!("/{query}"),
            path => path.to_owned(),
        };
        Some(Self {
            https,
            host: host.to_owned(),
            port,
            authority: authority.to_owned(),
            path,
        })
    }
}

/// Go's `splitHostPort` in `proxy_provider.go`: `[v6]:port` or `host:port`
/// at the last colon; the port may be empty.
fn split_host_port(authority: &str) -> Option<(&str, &str)> {
    if let Some(inner) = authority.strip_prefix('[') {
        let end = inner.rfind(']')?;
        let rest = &inner[end + 1..];
        return match rest.strip_prefix(':') {
            Some(port) => Some((&inner[..end], port)),
            None if rest.is_empty() => Some((&inner[..end], "")),
            None => None,
        };
    }
    Some(authority.rsplit_once(':').unwrap_or((authority, "")))
}

/// Go's `parsePortValue`: decimal digits only, 1 to 65535.
pub(crate) fn parse_port(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u16>().ok().filter(|port| *port > 0)
}

/// Go's `portFromURL`: only a port written in the URL, else 0.
pub(crate) fn port_from_url(raw: &str) -> u16 {
    let Some((_, rest)) = raw.split_once("://") else {
        return 0;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest[..end]
        .rsplit_once('@')
        .map_or(&rest[..end], |(_, h)| h);
    if authority.is_empty() {
        return 0;
    }
    split_host_port(authority)
        .and_then(|(_, port)| parse_port(port))
        .unwrap_or(0)
}

/// Go's `alternateSchemeURL`: the same URL with http and https swapped,
/// empty for another scheme.
pub(crate) fn alternate_scheme_url(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return String::new();
    };
    match scheme.to_ascii_lowercase().as_str() {
        "http" => format!("https://{rest}"),
        "https" => format!("http://{rest}"),
        _ => String::new(),
    }
}
