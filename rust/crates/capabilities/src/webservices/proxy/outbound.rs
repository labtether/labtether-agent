//! The Go agent's outbound rules (`securityruntime/outbound.go`), which
//! every NPM request passes: `ValidateOutboundURL` before the request and
//! for each redirect, and `dialOutboundValidated` for the addresses a
//! connection may use. Loopback is refused unless
//! `LABTETHER_OUTBOUND_ALLOW_LOOPBACK` is on; private addresses (and names
//! that look private) are allowed for https and wss unless
//! `LABTETHER_OUTBOUND_ALLOW_PRIVATE` says otherwise; http needs
//! `LABTETHER_ALLOW_INSECURE_TRANSPORT`; the allow list applies when its
//! mode is on. Traefik's and Caddy's requests do not pass these rules in
//! Go either.

use std::net::IpAddr;

use labtether_agent_config::OutboundSettings;

use crate::webservices::gourl;

const PRIVATE_SUFFIXES: [&str; 5] = [".local", ".lan", ".home", ".internal", ".home.arpa"];

/// Go's `normalizeHostname`.
pub(crate) fn normalize_host(value: &str) -> String {
    let host = value.trim().to_lowercase();
    let host = host.strip_prefix('[').unwrap_or(&host);
    let host = host.strip_suffix(']').unwrap_or(host);
    host.strip_suffix('.').unwrap_or(host).to_owned()
}

/// Go's `net.ParseIP` for a host: a plain IPv4 or IPv6 address (the
/// checks below read an IPv4-mapped address as IPv4).
fn parse_ip(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

fn is_loopback(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// Go's `isPrivateIPAddress`: private, link-local unicast or link-local
/// multicast.
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 224 && o[1] == 0 && o[2] == 0)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xff0f) == 0xff02
        }
    }
}

/// Go's `isLikelyPrivateHostname`.
fn likely_private_name(host: &str) -> bool {
    !host.is_empty() && (!host.contains('.') || PRIVATE_SUFFIXES.iter().any(|s| host.ends_with(s)))
}

/// Go's `net.ParseCIDR` and `Contains`.
fn cidr_contains(pattern: &str, ip: IpAddr) -> Option<bool> {
    let (addr, bits) = pattern.split_once('/')?;
    let base = addr.parse::<IpAddr>().ok()?;
    if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) || bits.len() > 3 {
        return None;
    }
    let bits: u32 = bits.parse().ok()?;
    let (net, ip, width) = match (base, ip.to_canonical()) {
        (IpAddr::V4(n), IpAddr::V4(i)) => (u128::from(n.to_bits()), u128::from(i.to_bits()), 32),
        (IpAddr::V6(n), IpAddr::V6(i)) => (n.to_bits(), i.to_bits(), 128),
        (IpAddr::V4(_), IpAddr::V6(_)) if bits <= 32 => return Some(false),
        (IpAddr::V6(_), IpAddr::V4(_)) if bits <= 128 => return Some(false),
        _ => return None,
    };
    if bits > width {
        return None;
    }
    let mask = if bits == 0 {
        0
    } else {
        (u128::MAX >> (128 - width)) & !((1u128 << (width - bits)) - 1)
    };
    Some(net & mask == ip & mask)
}

/// Go's `parseHostPattern`.
fn host_pattern(value: &str) -> String {
    let mut trimmed = value.trim().to_lowercase();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains("://")
        && let Some(url) = gourl::parse(&trimmed)
    {
        trimmed = url.hostname().to_owned();
    }
    if let Some(host) = split_host_port(&trimmed) {
        trimmed = host;
    }
    if trimmed.contains('/') && cidr_contains(&trimmed, IpAddr::from([0, 0, 0, 0])).is_some() {
        return trimmed;
    }
    normalize_host(&trimmed)
}

/// Go's `net.SplitHostPort`, the host when it splits.
fn split_host_port(value: &str) -> Option<String> {
    if let Some(inner) = value.strip_prefix('[') {
        let (host, rest) = inner.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        return (!port.contains([':', '[', ']']) && !host.contains('[')).then(|| host.to_owned());
    }
    let (host, port) = value.rsplit_once(':')?;
    (!host.contains(':') && !port.contains(['[', ']']) && !host.contains(['[', ']']))
        .then(|| host.to_owned())
}

/// Go's `hostMatchesPattern`.
fn matches_pattern(host: &str, pattern: &str) -> bool {
    let host = normalize_host(host);
    if host.is_empty() || pattern.is_empty() {
        return false;
    }
    if pattern.contains('/') {
        return parse_ip(&host)
            .and_then(|ip| cidr_contains(pattern, ip))
            .unwrap_or(false);
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return !suffix.is_empty() && host.ends_with(&format!(".{suffix}"));
    }
    host.eq_ignore_ascii_case(pattern)
}

/// The rules, read once from the settings.
#[derive(Debug, Clone, Default)]
pub(crate) struct Outbound {
    settings: OutboundSettings,
    patterns: Vec<String>,
}

impl Outbound {
    pub fn new(settings: &OutboundSettings) -> Self {
        Self {
            patterns: settings
                .allowed_hosts
                .iter()
                .map(|item| host_pattern(item))
                .filter(|p| !p.is_empty())
                .collect(),
            settings: settings.clone(),
        }
    }

    pub fn allow_loopback(&self) -> bool {
        self.settings.allow_loopback
    }

    /// Go's `resolvedOutboundAllowPrivate`.
    pub fn allow_private(&self, scheme: &str) -> bool {
        self.settings.allow_private.unwrap_or_else(|| {
            let scheme = scheme.trim();
            scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss")
        })
    }

    /// The host of `url` when Go would look it up to judge it: a name
    /// other than `localhost`.
    pub fn name_to_resolve(url: &str) -> Option<String> {
        let parsed = gourl::parse(url.trim())?;
        let host = normalize_host(parsed.hostname());
        (!host.is_empty() && parse_ip(&host).is_none() && !host.eq_ignore_ascii_case("localhost"))
            .then_some(host)
    }

    /// Go's `ValidateOutboundURL`. `resolved` holds the addresses of the
    /// name [`Self::name_to_resolve`] gave (`None` when the look-up failed).
    pub fn check_url(&self, raw: &str, resolved: Option<&[IpAddr]>) -> Result<(), String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("url is required".into());
        }
        let url = gourl::parse(trimmed).ok_or("invalid url")?;
        if url.scheme.is_empty() {
            return Err("url must be absolute".into());
        }
        if url.hostname().trim().is_empty() {
            return Err("url host is required".into());
        }
        let scheme = url.scheme.trim().to_lowercase();
        if (scheme == "http" || scheme == "ws") && !self.settings.allow_insecure {
            return Err(format!(
                "insecure url scheme {scheme:?} requires LABTETHER_ALLOW_INSECURE_TRANSPORT=true"
            ));
        }
        if !self
            .settings
            .schemes
            .iter()
            .any(|s| s.to_lowercase() == scheme)
        {
            return Err(format!("url scheme {scheme:?} is not allowed"));
        }
        self.check_host(url.hostname(), self.allow_private(&scheme), resolved)
    }

    /// Go's `validateOutboundHostWithPolicy`.
    fn check_host(
        &self,
        host: &str,
        allow_private: bool,
        resolved: Option<&[IpAddr]>,
    ) -> Result<(), String> {
        let host = normalize_host(host);
        if host.is_empty() {
            return Err("host is required".into());
        }
        let enforce = self.settings.allowlist_mode;
        let listed = enforce && self.patterns.iter().any(|p| matches_pattern(&host, p));
        let (loopback, private) = match (parse_ip(&host), resolved) {
            (Some(ip), _) => (is_loopback(ip), is_loopback(ip) || is_private(ip)),
            (None, _) if host.eq_ignore_ascii_case("localhost") => (true, true),
            (None, Some(ips)) if !ips.is_empty() => (
                ips.iter().any(|ip| is_loopback(*ip)),
                ips.iter().any(|ip| is_loopback(*ip) || is_private(*ip)),
            ),
            (None, _) => (false, likely_private_name(&host)),
        };
        let (allowed, kind) = if loopback {
            (self.settings.allow_loopback, "loopback")
        } else {
            (allow_private, "private")
        };
        if loopback || private {
            if !allowed {
                return Err(format!("outbound {kind} host {host:?} is not allowed"));
            }
            if enforce && !listed {
                return Err(format!("outbound host {host:?} is not allowlisted"));
            }
            return Ok(());
        }
        let ips = match parse_ip(&host) {
            Some(ip) => vec![ip],
            None => resolved.map(<[IpAddr]>::to_vec).unwrap_or_default(),
        };
        for ip in ips {
            check_ip(&host, ip, self.settings.allow_loopback, allow_private)?;
        }
        if enforce && !listed {
            return Err(format!("outbound host {host:?} is not allowlisted"));
        }
        Ok(())
    }
}

/// Go's `validateResolvedOutboundIP`, also each address a connection may
/// use (`dialOutboundValidated`).
pub(crate) fn check_ip(
    host: &str,
    ip: IpAddr,
    allow_loopback: bool,
    allow_private: bool,
) -> Result<(), String> {
    if is_loopback(ip) && !allow_loopback {
        return Err(format!(
            "outbound host {host:?} resolves to disallowed loopback address {ip}"
        ));
    }
    if is_private(ip) && !allow_private {
        return Err(format!(
            "outbound host {host:?} resolves to disallowed private address {ip}"
        ));
    }
    Ok(())
}
