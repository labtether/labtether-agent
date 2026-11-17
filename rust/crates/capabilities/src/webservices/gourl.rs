//! Go's `net/url` (Go 1.27) as far as the web service page reads URLs:
//! `Parse` with its checks (control bytes, scheme, `//` authority, user
//! info, host characters and `%` escapes, a numeric port, one colon in an
//! http(s) host, bracketed IPv6 only), `Hostname`, `Port`, `EscapedPath`,
//! and `ResolveReference` for a redirect's `Location`. A URL Go refuses
//! gives `None` here: a route's backend counts as Go counts it, and no
//! probe goes to a URL Go's `http.NewRequest` would refuse (a proxy's
//! backend such as `{upstream}:3000`).

use std::net::Ipv6Addr;

/// The parts of Go's `url.URL` read here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GoUrl {
    /// Lower case.
    pub scheme: String,
    pub opaque: String,
    /// Go's `URL.User != nil`; the user info as written.
    pub user: Option<String>,
    /// Go's `URL.Host`: unescaped, `[v6]:port` for IPv6.
    pub host: String,
    /// Unescaped bytes (Go's string may hold any bytes).
    pub path: Vec<u8>,
    raw_path: String,
    pub raw_query: String,
    pub force_query: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    Host,
    Zone,
    Other,
}

/// Go's `shouldEscape` for the modes read here.
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone) && b"!$&'()*+,;=:[]<>\"".contains(&c) {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => {
            mode != Mode::Path || c == b'?'
        }
        _ => true,
    }
}

fn unhex(c: u8) -> u8 {
    9 * (c >> 6) + (c & 15)
}

/// Go's `unescape`: `None` for a bad escape or, in a host, a character Go
/// refuses.
fn unescape(s: &str, mode: Mode) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes.get(i + 1..i + 3)?;
                if !pair.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                let v = (unhex(pair[0]) << 4) | unhex(pair[1]);
                let is25 = &s[i..i + 3] == "%25";
                if mode == Mode::Host && unhex(pair[0]) < 8 && !is25 {
                    return None;
                }
                if mode == Mode::Zone && !is25 && v != b' ' && should_escape(v, Mode::Host) {
                    return None;
                }
                out.push(v);
                i += 3;
            }
            c => {
                if matches!(mode, Mode::Host | Mode::Zone) && c < 0x80 && should_escape(c, mode) {
                    return None;
                }
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

fn unescape_text(s: &str, mode: Mode) -> Option<String> {
    unescape(s, mode).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Go's `escape(s, encodePath)`.
fn escape_path(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s {
        if should_escape(c, Mode::Path) {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(char::from(c));
        }
    }
    out
}

/// Go's `validOptionalPort`.
fn valid_optional_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Go's `getScheme`: `Err` for a leading `:`.
fn get_scheme(raw: &str) -> Result<(&str, &str), ()> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i == 0 => return Err(()),
            b':' => return Ok((&raw[..i], &raw[i + 1..])),
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

/// Go's `parseHost`.
fn parse_host(scheme: &str, host: &str) -> Option<String> {
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return None;
        }
        let close = host.rfind(']')?;
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return None;
        }
        let inner = &host[1..close];
        let unescaped = match inner.find("%25") {
            Some(zone) => {
                unescape_text(&inner[..zone], Mode::Host)?
                    + &unescape_text(&inner[zone..], Mode::Zone)?
            }
            None => unescape_text(inner, Mode::Host)?,
        };
        // Go's netip.ParseAddr, IPv6 only (a zone after `%`, not empty).
        let (addr, zone) = unescaped.split_once('%').unwrap_or((&unescaped, ""));
        if unescaped.contains('%') && zone.is_empty() {
            return None;
        }
        addr.parse::<Ipv6Addr>().ok()?;
        return Some(format!("[{unescaped}]{colon_port}"));
    }
    if let Some(first) = host.find(':') {
        let last = host.rfind(':').unwrap_or(first);
        // Go 1.27 refuses a second colon in an http or https host.
        let at = if scheme == "http" || scheme == "https" {
            first
        } else {
            last
        };
        if !valid_optional_port(&host[at..]) {
            return None;
        }
    }
    unescape_text(host, Mode::Host)
}

/// Go's `validUserinfo`.
fn valid_userinfo(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-._:~!$&'()*+,;=%@".contains(c))
}

/// Go's `url.Parse`.
pub(crate) fn parse(raw: &str) -> Option<GoUrl> {
    let (raw, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let url = parse_without_fragment(raw)?;
    if !fragment.is_empty() {
        unescape(fragment, Mode::Other)?;
    }
    Some(url)
}

fn parse_without_fragment(raw: &str) -> Option<GoUrl> {
    if raw.bytes().any(|b| b < b' ' || b == 0x7f) {
        return None;
    }
    let mut url = GoUrl::default();
    if raw == "*" {
        url.path = b"*".to_vec();
        return Some(url);
    }
    let (scheme, mut rest) = get_scheme(raw).ok()?;
    url.scheme = scheme.to_ascii_lowercase();
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else if let Some((before, query)) = rest.split_once('?') {
        url.raw_query = query.to_owned();
        rest = before;
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_owned();
            return Some(url);
        }
        if rest.split('/').next().unwrap_or("").contains(':') {
            return None;
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let authority = &rest[2..];
        let end = authority.find('/').unwrap_or(authority.len());
        let (authority, path) = authority.split_at(end);
        rest = path;
        let (user, host) = match authority.rfind('@') {
            Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
            None => (None, authority),
        };
        url.host = parse_host(&url.scheme, host)?;
        if let Some(user) = user {
            if !valid_userinfo(user) {
                return None;
            }
            for part in user.splitn(2, ':') {
                unescape(part, Mode::Other)?;
            }
            url.user = Some(user.to_owned());
        }
    }
    url.set_path(rest)?;
    Some(url)
}

impl GoUrl {
    /// Go's `setPath`.
    fn set_path(&mut self, p: &str) -> Option<()> {
        self.path = unescape(p, Mode::Path)?;
        self.raw_path = if escape_path(&self.path) == p {
            String::new()
        } else {
            p.to_owned()
        };
        Some(())
    }

    /// Sets the path as Go's `npmEndpointURL` does: raw path, query and
    /// fragment cleared.
    pub fn set_plain_path(&mut self, path: Vec<u8>) {
        self.path = path;
        self.raw_path.clear();
        self.raw_query.clear();
    }

    /// Go's `URL.String` for the URLs read here (user info as written).
    pub fn text(&self) -> String {
        if !self.opaque.is_empty() {
            return format!("{}:{}", self.scheme, self.opaque);
        }
        let path = self.escaped_path();
        let slash = if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
            "/"
        } else {
            ""
        };
        let query = if self.force_query || !self.raw_query.is_empty() {
            format!("?{}", self.raw_query)
        } else {
            String::new()
        };
        let user = self
            .user
            .as_deref()
            .map_or(String::new(), |u| format!("{u}@"));
        format!("{}://{user}{}{slash}{path}{query}", self.scheme, self.host)
    }

    /// Go's `EscapedPath`.
    pub fn escaped_path(&self) -> String {
        let valid = |s: &str| {
            s.bytes()
                .all(|c| b"!$&'()*+,;=:@[]%".contains(&c) || !should_escape(c, Mode::Path))
        };
        if !self.raw_path.is_empty()
            && valid(&self.raw_path)
            && unescape(&self.raw_path, Mode::Path).as_deref() == Some(self.path.as_slice())
        {
            return self.raw_path.clone();
        }
        if self.path == b"*" {
            return "*".into();
        }
        escape_path(&self.path)
    }

    /// Go's `splitHostPort` of `url.go`: the port only when numeric.
    fn split(&self) -> (&str, &str) {
        let mut host = self.host.as_str();
        let mut port = "";
        if let Some(colon) = host.rfind(':')
            && valid_optional_port(&host[colon..])
        {
            port = &host[colon + 1..];
            host = &host[..colon];
        }
        if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            host = inner;
        }
        (host, port)
    }

    pub fn hostname(&self) -> &str {
        self.split().0
    }

    pub fn port(&self) -> &str {
        self.split().1
    }

    /// Go's `ResolveReference` with `reference` parsed by [`parse`].
    pub fn resolve(&self, reference: &GoUrl) -> GoUrl {
        let mut url = reference.clone();
        if reference.scheme.is_empty() {
            url.scheme.clone_from(&self.scheme);
        }
        if !reference.scheme.is_empty() || !reference.host.is_empty() || reference.user.is_some() {
            let _ = url.set_path(&resolve_path(&reference.escaped_path(), ""));
            return url;
        }
        if !reference.opaque.is_empty() {
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        if reference.path.is_empty() && !reference.force_query && reference.raw_query.is_empty() {
            url.raw_query.clone_from(&self.raw_query);
        }
        if reference.path.is_empty() && !self.opaque.is_empty() {
            url.opaque.clone_from(&self.opaque);
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        url.host.clone_from(&self.host);
        url.user.clone_from(&self.user);
        let _ = url.set_path(&resolve_path(
            &self.escaped_path(),
            &reference.escaped_path(),
        ));
        url
    }
}

/// Go's `resolvePath`.
fn resolve_path(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_owned()
    } else if !reference.starts_with('/') {
        let cut = base.rfind('/').map_or(0, |i| i + 1);
        format!("{}{reference}", &base[..cut])
    } else {
        reference.to_owned()
    };
    if full.is_empty() {
        return String::new();
    }
    let mut dst = String::from("/");
    let mut first = true;
    let mut last = "";
    for elem in full.split('/') {
        last = elem;
        match elem {
            "." => first = false,
            ".." => {
                match dst[1..].rfind('/') {
                    Some(i) => dst.truncate(i + 1),
                    None => dst.truncate(1),
                }
                first = dst.len() == 1;
            }
            _ => {
                if !first {
                    dst.push('/');
                }
                dst.push_str(elem);
                first = false;
            }
        }
    }
    if last == "." || last == ".." {
        dst.push('/');
    }
    if dst.len() > 1 && dst.as_bytes()[1] == b'/' {
        return dst[1..].to_owned();
    }
    dst
}
