//! Go's `sameOriginRedirectURL` (`fingerprinting.go`) with the parts of
//! Go's `net/url` it runs (`Parse`, `ResolveReference`, `String`): the
//! redirect target is read as a URL reference and resolved against the
//! probed URL, and only its path and query are kept, on the probed scheme
//! and host, so a probe never moves to another host. A target Go's parser
//! refuses gives no URL.

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Go's `encoding` modes this needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    Host,
    Zone,
    UserPassword,
    Fragment,
}

/// Go's `shouldEscape`.
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Mode::Fragment => return false,
            Mode::Host | Mode::Zone => {}
        },
        _ => {}
    }
    !(mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*'))
}

fn hex(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Go's `unescape` (no `+` rule: no query component here).
fn unescape(s: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let value = hex(*s.get(i + 1)?)? << 4 | hex(*s.get(i + 2)?)?;
            let percent = &s[i..i + 3] == b"%25";
            if mode == Mode::Host && value < 0x80 && !percent {
                return None;
            }
            if mode == Mode::Zone && !percent && value != b' ' && should_escape(value, Mode::Host) {
                return None;
            }
            out.push(value);
            i += 3;
        } else {
            if matches!(mode, Mode::Host | Mode::Zone) && s[i] < 0x80 && should_escape(s[i], mode) {
                return None;
            }
            out.push(s[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Go's `escape` for a path.
fn escape_path(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s {
        if should_escape(c, Mode::Path) {
            out.extend([
                '%',
                char::from(HEX[usize::from(c >> 4)]),
                char::from(HEX[usize::from(c & 15)]),
            ]);
        } else {
            out.push(char::from(c));
        }
    }
    out
}

/// The fields of Go's `URL` that the resolution reads.
#[derive(Debug, Default)]
struct Reference {
    scheme: String,
    opaque: String,
    host: String,
    user: bool,
    path: Vec<u8>,
    raw_path: String,
    raw_query: String,
    force_query: bool,
}

impl Reference {
    /// Go's `setPath`: the decoded path, and the written one when it is
    /// not the default escaping.
    fn set_path(&mut self, written: &str) -> Option<()> {
        self.path = unescape(written.as_bytes(), Mode::Path)?;
        self.raw_path = if escape_path(&self.path) == written {
            String::new()
        } else {
            written.to_owned()
        };
        Some(())
    }

    /// Go's `EscapedPath`.
    fn escaped_path(&self) -> String {
        let valid = self.raw_path.bytes().all(|c| {
            matches!(
                c,
                b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
            ) || matches!(c, b':' | b'@' | b'[' | b']' | b'%')
                || !should_escape(c, Mode::Path)
        });
        if !self.raw_path.is_empty()
            && valid
            && unescape(self.raw_path.as_bytes(), Mode::Path).as_deref() == Some(&self.path[..])
        {
            return self.raw_path.clone();
        }
        if self.path == b"*" {
            return "*".to_owned();
        }
        escape_path(&self.path)
    }

    /// Go's `url.Parse`.
    fn parse(raw: &str) -> Option<Self> {
        let (u, fragment) = raw.split_once('#').unwrap_or((raw, ""));
        if u.bytes().any(|b| b < b' ' || b == 0x7f) {
            return None;
        }
        let mut url = Self::default();
        if u == "*" {
            url.path = b"*".to_vec();
        } else {
            url.parse_rest(u)?;
        }
        unescape(fragment.as_bytes(), Mode::Fragment)?;
        Some(url)
    }

    fn parse_rest(&mut self, u: &str) -> Option<()> {
        let mut rest = u;
        for (i, c) in u.bytes().enumerate() {
            match c {
                b'a'..=b'z' | b'A'..=b'Z' => {}
                b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
                b':' if i == 0 => return None,
                b':' => {
                    self.scheme = u[..i].to_ascii_lowercase();
                    rest = &u[i + 1..];
                    break;
                }
                _ => break,
            }
        }
        if rest.ends_with('?') && rest.matches('?').count() == 1 {
            self.force_query = true;
            rest = &rest[..rest.len() - 1];
        } else if let Some((before, query)) = rest.split_once('?') {
            self.raw_query = query.to_owned();
            rest = before;
        }
        if !rest.starts_with('/') {
            if !self.scheme.is_empty() {
                self.opaque = rest.to_owned();
                return Some(());
            }
            if rest.split('/').next().unwrap_or("").contains(':') {
                return None;
            }
        }
        if (!self.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
            let authority = &rest[2..];
            let end = authority.find('/').unwrap_or(authority.len());
            self.parse_authority(&authority[..end])?;
            rest = &authority[end..];
        }
        self.set_path(rest)
    }

    /// Go's `parseAuthority`: only whether it parses matters here.
    fn parse_authority(&mut self, authority: &str) -> Option<()> {
        let (user, host) = match authority.rfind('@') {
            Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
            None => (None, authority),
        };
        self.host = parse_host(&self.scheme, host)?;
        if let Some(user) = user {
            let allowed = |c: char| c.is_ascii_alphanumeric() || "-._:~!$&'()*+,;=%@".contains(c);
            if !user.chars().all(allowed) {
                return None;
            }
            for part in user.splitn(2, ':') {
                unescape(part.as_bytes(), Mode::UserPassword)?;
            }
            self.user = true;
        }
        Some(())
    }
}

/// Go's `validOptionalPort`.
fn valid_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()))
}

/// Go's `parseHost`: the host decoded, or `None` when Go refuses it.
fn parse_host(scheme: &str, host: &str) -> Option<String> {
    match host.rfind('[') {
        Some(open) if open > 0 => return None,
        Some(_) => {
            let close = host.rfind(']')?;
            let port = &host[close + 1..];
            if !valid_port(port) {
                return None;
            }
            unescape(port.as_bytes(), Mode::Host)?;
            let name = host.get(1..close)?;
            let (address, zone) = match name.find("%25") {
                Some(z) => (&name[..z], Some(&name[z..])),
                None => (name, None),
            };
            let address = String::from_utf8(unescape(address.as_bytes(), Mode::Host)?).ok()?;
            // Go's `netip.ParseAddr`: an IPv6 address, any zone not empty.
            if let Some(zone) = zone
                && unescape(zone.as_bytes(), Mode::Zone)?.len() < 2
            {
                return None;
            }
            address.parse::<std::net::Ipv6Addr>().ok()?;
            return Some(host.to_owned());
        }
        None => {
            if let Some(first) = host.find(':') {
                let last = host.rfind(':').unwrap_or(first);
                let strict = scheme == "http" || scheme == "https";
                let at = if strict { first } else { last };
                if !valid_port(&host[at..]) {
                    return None;
                }
            }
        }
    }
    Some(String::from_utf8_lossy(&unescape(host.as_bytes(), Mode::Host)?).into_owned())
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
                let keep = dst[1..].rfind('/').map_or(1, |i| i + 1);
                dst.truncate(keep);
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
        dst.remove(0);
    }
    dst
}

/// Go's `sameOriginRedirectURL(fromURL, location)`.
pub(crate) fn same_origin_redirect(from: &str, location: &str) -> String {
    if location.trim().is_empty() {
        return String::new();
    }
    let (Some(from), Some(target)) = (Reference::parse(from), Reference::parse(location)) else {
        return String::new();
    };
    // Go's `ResolveReference`, for the path and query only.
    let (resolved, query) = if !target.scheme.is_empty() || !target.host.is_empty() || target.user {
        (resolve_path(&target.escaped_path(), ""), target.raw_query)
    } else if !target.opaque.is_empty() {
        (String::new(), target.raw_query)
    } else {
        let query = if target.path.is_empty() && !target.force_query && target.raw_query.is_empty()
        {
            from.raw_query.clone()
        } else {
            target.raw_query.clone()
        };
        (
            resolve_path(&from.escaped_path(), &target.escaped_path()),
            query,
        )
    };
    let path = unescape(resolved.as_bytes(), Mode::Path).unwrap_or_default();
    // Go's `String` of `URL{Scheme, Host, Path, RawQuery}`.
    let mut out = String::new();
    if !from.scheme.is_empty() {
        out.push_str(&from.scheme);
        out.push(':');
    }
    if !from.scheme.is_empty() || !from.host.is_empty() {
        if !from.host.is_empty() || !path.is_empty() {
            out.push_str("//");
        }
        for c in from.host.bytes() {
            if should_escape(c, Mode::Host) {
                out.extend([
                    '%',
                    char::from(HEX[usize::from(c >> 4)]),
                    char::from(HEX[usize::from(c & 15)]),
                ]);
            } else {
                out.push(char::from(c));
            }
        }
    }
    let escaped = escape_path(&path);
    if !escaped.is_empty() && !escaped.starts_with('/') && !from.host.is_empty() {
        out.push('/');
    }
    out.push_str(&escaped);
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    out
}
