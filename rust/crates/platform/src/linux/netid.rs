//! The device's LAN address and Wake-on-LAN MAC, ported from Go's
//! `internal/agentplatform/netid`. The interface list comes from the route
//! netlink socket (`netlink.rs`), as Go's `net.Interfaces` reads it.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// One network interface: what `PrimaryIP` and `PrimaryMAC` look at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Nic {
    pub name: String,
    /// The hardware address when the kernel reports a non-zero one.
    pub mac: Vec<u8>,
    pub up: bool,
    pub loopback: bool,
    /// Addresses in the kernel's order (IPv4 before IPv6).
    pub ips: Vec<IpAddr>,
}

/// Go's `DefaultRouteIP`: the local address the kernel picks to reach a
/// documentation address. A UDP connect sends no packet.
pub fn default_route_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

const HOST_IP_VIRTUAL: [&str; 16] = [
    "docker",
    "br-",
    "veth",
    "virbr",
    "vnet",
    "tailscale",
    "tun",
    "tap",
    "wg",
    "zt",
    "utun",
    "lxc",
    "cni",
    "flannel",
    "cali",
    "kube",
];
const MAC_VIRTUAL: [&str; 15] = [
    "docker",
    "veth",
    "br-",
    "virbr",
    "vnet",
    "tailscale",
    "tun",
    "tap",
    "wg",
    "zt",
    "lxc",
    "cni",
    "flannel",
    "cali",
    "kube",
];

fn has_prefix(name: &str, prefixes: &[&str]) -> bool {
    let name = name.to_lowercase();
    prefixes.iter().any(|prefix| name.starts_with(prefix))
}

/// An IPv6 address that holds an IPv4 one, as Go's `To4` reads it.
fn as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Go's `hostIPRank`: lower is better, `None` means never.
pub fn host_ip_rank(interface: &str, ip: IpAddr) -> Option<u8> {
    let unusable = match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
        }
    };
    if unusable {
        return None;
    }
    let virtual_iface = has_prefix(interface, &HOST_IP_VIRTUAL);
    let Some(v4) = as_v4(ip) else {
        return Some(5);
    };
    let octets = v4.octets();
    let cgnat = octets[0] == 100 && octets[1] & 0xC0 == 64;
    Some(match (cgnat, virtual_iface, v4.is_private()) {
        (true, _, _) => 4,
        (false, false, true) => 0,
        (false, false, false) => 1,
        (false, true, true) => 2,
        (false, true, false) => 3,
    })
}

/// Go's `ip.String()`: an IPv4-mapped IPv6 address prints as IPv4.
fn go_ip_string(ip: IpAddr) -> String {
    as_v4(ip).map_or_else(|| ip.to_string(), |v4| v4.to_string())
}

fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    match (as_v4(a), as_v4(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

/// Go's `chooseHostIP`: the default route's address when it is a LAN
/// address (rank 0 or 1), else the best ranked one, interface order first.
pub fn choose_host_ip(candidates: &[(String, IpAddr)], route: Option<IpAddr>) -> String {
    let mut best: Option<(u8, IpAddr)> = None;
    for (interface, ip) in candidates {
        let Some(rank) = host_ip_rank(interface, *ip) else {
            continue;
        };
        if rank <= 1 && route.is_some_and(|route| same_ip(*ip, route)) {
            return go_ip_string(*ip);
        }
        if best.is_none_or(|(best_rank, _)| rank < best_rank) {
            best = Some((rank, *ip));
        }
    }
    best.map(|(_, ip)| go_ip_string(ip)).unwrap_or_default()
}

/// Go's `PrimaryIP` candidates: addresses of interfaces that are up and not
/// loopback, in interface order.
pub fn primary_ip(nics: &[Nic], route: Option<IpAddr>) -> String {
    let candidates: Vec<(String, IpAddr)> = nics
        .iter()
        .filter(|nic| nic.up && !nic.loopback)
        .flat_map(|nic| nic.ips.iter().map(|ip| (nic.name.clone(), *ip)))
        .collect();
    choose_host_ip(&candidates, route)
}

fn mac_string(mac: &[u8]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Go's `choosePrimaryMAC`: the MAC of the interface holding the default
/// route's address, else of the first wired-looking interface by name that
/// is up and has an address, else empty.
pub fn primary_mac(nics: &[Nic], route: Option<IpAddr>) -> String {
    let usable = |nic: &Nic| nic.up && !nic.loopback && nic.mac.len() == 6;
    if let Some(route) = route
        && let Some(nic) = nics
            .iter()
            .find(|nic| usable(nic) && nic.ips.iter().any(|ip| same_ip(*ip, route)))
    {
        return mac_string(&nic.mac);
    }
    let mut sorted: Vec<&Nic> = nics.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    sorted
        .into_iter()
        .find(|nic| usable(nic) && !nic.ips.is_empty() && !has_prefix(&nic.name, &MAC_VIRTUAL))
        .map(|nic| mac_string(&nic.mac))
        .unwrap_or_default()
}
