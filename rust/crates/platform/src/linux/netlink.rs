//! The interface list from the route netlink socket, as Go's
//! `net.Interfaces` and `Interface.Addrs` read it on Linux: one
//! `RTM_GETLINK` dump for names, flags and MAC addresses and one
//! `RTM_GETADDR` dump for addresses. Read once at start.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

use super::netid::Nic;

const HEADER: usize = 16;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
pub const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const SEQ: u32 = 1;

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// Splits a netlink buffer into `(type, sequence, payload)` messages.
pub fn messages(buffer: &[u8]) -> Vec<(u16, u32, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + HEADER <= buffer.len() {
        let (Some(len), Some(kind), Some(seq)) = (
            u32_at(buffer, at).and_then(|len| usize::try_from(len).ok()),
            u16_at(buffer, at + 4),
            u32_at(buffer, at + 8),
        ) else {
            break;
        };
        if len < HEADER || at + len > buffer.len() {
            break;
        }
        out.push((kind, seq, &buffer[at + HEADER..at + len]));
        at += align4(len);
    }
    out
}

/// Route attributes `(type, value)` after a fixed-size header.
pub fn attributes(payload: &[u8], fixed: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = fixed;
    while at + 4 <= payload.len() {
        let (Some(len), Some(kind)) = (u16_at(payload, at), u16_at(payload, at + 2)) else {
            break;
        };
        let len = usize::from(len);
        if len < 4 || at + len > payload.len() {
            break;
        }
        out.push((kind & 0x3fff, &payload[at + 4..at + len]));
        at += align4(len);
    }
    out
}

/// An `RTM_NEWLINK` payload as `(index, interface)`. The MAC is kept only
/// when not all zero, as Go does.
pub fn parse_link(payload: &[u8]) -> Option<(i32, Nic)> {
    let index = i32::from_ne_bytes(payload.get(4..8)?.try_into().ok()?);
    let flags = u32_at(payload, 8)?;
    let mut nic = Nic {
        up: flags & IFF_UP != 0,
        loopback: flags & IFF_LOOPBACK != 0,
        ..Nic::default()
    };
    for (kind, value) in attributes(payload, 16) {
        match kind {
            IFLA_IFNAME => {
                let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
                nic.name = String::from_utf8_lossy(&value[..end]).into_owned();
            }
            IFLA_ADDRESS if value.iter().any(|b| *b != 0) => nic.mac = value.to_vec(),
            _ => {}
        }
    }
    Some((index, nic))
}

/// An `RTM_NEWADDR` payload as `(index, address)`: `IFA_LOCAL` when given
/// (point-to-point and every IPv4 address), else `IFA_ADDRESS`.
pub fn parse_address(payload: &[u8]) -> Option<(i32, IpAddr)> {
    let family = *payload.first()?;
    let index = i32::from_ne_bytes(payload.get(4..8)?.try_into().ok()?);
    let attrs = attributes(payload, 8);
    let pick = |want: u16| {
        attrs
            .iter()
            .find(|(kind, _)| *kind == want)
            .map(|(_, v)| *v)
    };
    let value = pick(IFA_LOCAL).or_else(|| pick(IFA_ADDRESS))?;
    let ip = match family {
        AF_INET => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(value.get(..4)?).ok()?)),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(value.get(..16)?).ok()?)),
        _ => return None,
    };
    Some((index, ip))
}

/// Interfaces in the kernel's order, each with its addresses.
pub fn interfaces_from(links: &[&[u8]], addresses: &[&[u8]]) -> Vec<Nic> {
    let addrs: Vec<(i32, IpAddr)> = addresses.iter().filter_map(|p| parse_address(p)).collect();
    links
        .iter()
        .filter_map(|payload| parse_link(payload))
        .map(|(index, mut nic)| {
            nic.ips = addrs
                .iter()
                .filter(|(i, _)| *i == index)
                .map(|(_, ip)| *ip)
                .collect();
            nic
        })
        .collect()
}

/// One dump request; returns the payloads of `want` messages.
fn dump(request: u16, want: u16) -> io::Result<Vec<Vec<u8>>> {
    let fd = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None, // NETLINK_ROUTE
    )?;
    // nlmsghdr + rtgenmsg { family: AF_UNSPEC }, 17 bytes as Go sends it.
    let mut message = [0u8; HEADER + 1];
    message[0..4].copy_from_slice(&17u32.to_ne_bytes());
    message[4..6].copy_from_slice(&request.to_ne_bytes());
    message[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    message[8..12].copy_from_slice(&SEQ.to_ne_bytes());
    rustix::net::sendto(
        &fd,
        &message,
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut out = Vec::new();
    loop {
        let (read, _) = rustix::net::recv(&fd, &mut buffer[..], RecvFlags::empty())?;
        for (kind, seq, payload) in messages(&buffer[..read]) {
            if seq != SEQ {
                continue;
            }
            match kind {
                NLMSG_DONE => return Ok(out),
                NLMSG_ERROR => return Err(io::Error::other("netlink dump refused")),
                kind if kind == want => out.push(payload.to_vec()),
                _ => {}
            }
        }
        if read == 0 {
            return Ok(out);
        }
    }
}

/// Every interface with its flags, MAC and addresses.
pub fn interfaces() -> io::Result<Vec<Nic>> {
    let links = dump(RTM_GETLINK, RTM_NEWLINK)?;
    let addresses = dump(RTM_GETADDR, RTM_NEWADDR)?;
    let links: Vec<&[u8]> = links.iter().map(Vec::as_slice).collect();
    let addresses: Vec<&[u8]> = addresses.iter().map(Vec::as_slice).collect();
    Ok(interfaces_from(&links, &addresses))
}
