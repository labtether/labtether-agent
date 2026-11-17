//! The host's listening TCP ports, from `/proc/net/tcp` and `/proc/net/tcp6`:
//! Go's `parseProcNetListeningPorts` (`webservice/scan_parsers.go`) and
//! `detectListeningTCPPorts` (`scan_discovery.go`). The web service page's
//! local scan adds these ports to the ones it checks.

use std::path::Path;

/// Go's `parseProcNetListeningPorts`: the local port of each socket in the
/// listening state (`0A`), in the file's order. The first line is the
/// header and is skipped, whatever it holds.
pub fn listening_ports(text: &str) -> Vec<u16> {
    text.split('\n')
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || !fields[3].eq_ignore_ascii_case("0A") {
                return None;
            }
            let (_, hex) = fields[1].rsplit_once(':')?;
            parse_hex_port(hex)
        })
        .collect()
}

/// Go's `strconv.ParseInt(hex, 16, 32)` kept between 1 and 65535: an
/// optional sign, then hex digits only.
fn parse_hex_port(raw: &str) -> Option<u16> {
    let (negative, digits) = match raw.as_bytes().first()? {
        b'+' => (false, &raw[1..]),
        b'-' => (true, &raw[1..]),
        _ => (false, raw),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u64::from_str_radix(digits, 16).ok()?;
    if negative {
        return None;
    }
    u16::try_from(value).ok().filter(|port| *port > 0)
}

/// Go's `detectListeningTCPPorts` over the two files' text: both lists,
/// each port once, sorted.
pub fn listening_tcp_ports(tcp: &str, tcp6: &str) -> Vec<u16> {
    let mut ports = listening_ports(tcp);
    ports.extend(listening_ports(tcp6));
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Reads the two files; one that cannot be read counts as empty, as Go's
/// `readFileString`.
pub fn read_listening_tcp_ports(proc_root: &Path) -> Vec<u16> {
    let read = |name: &str| std::fs::read_to_string(proc_root.join(name)).unwrap_or_default();
    listening_tcp_ports(&read("net/tcp"), &read("net/tcp6"))
}
