//! The interface list behind `network.list` on macOS, ported from Go's
//! `collectNetInterfaces` (`internal/agentcore/sysconfig/network_handler.go`)
//! and `ReadIfaceStats` (`network_stats_darwin.go`): every interface in
//! index order except loopback, with its state, MAC, MTU, addresses as
//! `address/prefix` and four counters.
//!
//! Go reads the counters by running `netstat -bI <name>` once per interface
//! and keeping the row with the most bytes, which is the link row; this
//! reads the same link counters from the interface table without starting
//! `netstat`.
//!
//! The MAC: macOS 27 gives a process started under a non-Apple program the
//! placeholder `02:00:00:00:00:00` for every interface. Go then runs
//! `networksetup -listallhardwareports` for the real address. A sandboxed
//! agent may start no program, so here a placeholder becomes an empty MAC
//! (what Go sends when `networksetup` has no address for the port) and is
//! never sent as if it were real.

use std::net::IpAddr;

use super::netid::Nic;
use super::route::{self, Link};

/// One row, as Go fills `protocol.NetInterface`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceRow {
    pub name: String,
    /// `up` when `IFF_UP` is set, else `down`.
    pub state: &'static str,
    /// Lowercase hex bytes joined by `:`, empty without a real address.
    pub mac: String,
    pub mtu: i64,
    pub ips: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Go's `netid.IsPlaceholderMAC`: the macOS redaction value or all zeros.
pub fn is_placeholder_mac(mac: &[u8]) -> bool {
    !mac.is_empty() && (mac == [2, 0, 0, 0, 0, 0] || mac.iter().all(|b| *b == 0))
}

/// The MAC Go reports for an interface whose `networksetup` lookup found
/// nothing: the address unless it is a placeholder.
fn real_mac(mac: &[u8]) -> &[u8] {
    if is_placeholder_mac(mac) { &[] } else { mac }
}

/// Go's `HardwareAddr.String`.
pub fn mac_text(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Go's `IP.String`: an IPv4-mapped IPv6 address prints as IPv4.
fn go_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Go's `simpleMaskLength`: the number of leading one bits, or `None` when
/// a one follows a zero.
pub fn prefix_len(mask: &[u8]) -> Option<u32> {
    let mut seen_zero = false;
    let mut count = 0u32;
    for byte in mask {
        for bit in (0..8).rev() {
            let one = byte >> bit & 1 == 1;
            if one && seen_zero {
                return None;
            }
            seen_zero |= !one;
            count += u32::from(one);
        }
    }
    Some(count)
}

/// Go's `IPNet.String` for an interface address: the address (not masked),
/// then `/prefix`, or `/hexmask` for a mask that is not a prefix, or
/// `<nil>` when address and mask do not fit together.
pub fn address_text(ip: IpAddr, mask: &[u8]) -> String {
    let ip = go_ip(ip);
    let mask = match (ip, mask.len()) {
        (IpAddr::V4(_), 4) | (IpAddr::V6(_), 16) => mask,
        (IpAddr::V4(_), 16) => &mask[12..],
        _ => return "<nil>".to_owned(),
    };
    match prefix_len(mask) {
        Some(len) => format!("{ip}/{len}"),
        None => format!(
            "{ip}/{}",
            mask.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
    }
}

/// Rows for `links` in their order, loopback left out.
pub fn rows(links: &[Link]) -> Vec<InterfaceRow> {
    links
        .iter()
        .filter(|link| !link.loopback())
        .map(|link| InterfaceRow {
            name: link.name.clone(),
            state: if link.up() { "up" } else { "down" },
            mac: mac_text(real_mac(&link.mac)),
            mtu: i64::from(link.mtu),
            ips: link
                .addrs
                .iter()
                .map(|(ip, mask)| address_text(*ip, mask))
                .collect(),
            rx_bytes: link.rx_bytes,
            tx_bytes: link.tx_bytes,
            rx_packets: link.rx_packets,
            tx_packets: link.tx_packets,
        })
        .collect()
}

/// What `netid::primary_ip` and `primary_mac` look at, with placeholders
/// removed (Go's `listNICs` with a `MACResolver` that found nothing).
pub fn nics(links: &[Link]) -> Vec<Nic> {
    links
        .iter()
        .map(|link| Nic {
            name: link.name.clone(),
            mac: real_mac(&link.mac).to_vec(),
            up: link.up(),
            loopback: link.loopback(),
            ips: link.addrs.iter().map(|(ip, _)| go_ip(*ip)).collect(),
            prefixes: link
                .addrs
                .iter()
                .map(|(_, mask)| prefix_len(mask).map_or(0, |n| n as u8))
                .collect(),
            mtu: link.mtu,
        })
        .collect()
}

/// The interface list of this host.
pub fn interface_rows() -> std::io::Result<Vec<InterfaceRow>> {
    Ok(rows(&route::links()?))
}
