//! The kernel's interface table (`sysctl NET_RT_IFLIST2`), parsed in safe
//! code: each interface's name, flags, MTU, link address and addresses with
//! their masks. The counters come from a second dump,
//! `net.link.generic.ifalldata`: in the interface table the kernel cuts each
//! byte counter to its low 32 bits, rounded down to 1 KiB, for any program
//! that is not part of macOS (`netstat` is, so it sees whole values).
//!
//! This is what both Go readers see on macOS: Go's `net.Interfaces` and
//! `Interface.Addrs` parse the same messages (`NET_RT_IFLIST`, through
//! `golang.org/x/net/route`), and `netstat -i`, which gopsutil and the
//! network page run, prints the link counters of these `RTM_IFINFO2`
//! messages. The socket address rules follow `x/net/route`
//! (`parseAddrs`, `parseInetAddr`, `parseKernelInetAddr`,
//! `parseKernelLinkAddr`), so a mask or a link-local address reads the way
//! Go reads it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use labtether_agent_macos_sys::layout as l;

/// One interface and its addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    pub index: u16,
    pub name: String,
    /// `IFF_*` flags.
    pub flags: i32,
    pub mtu: u32,
    /// The link address as the kernel gives it: empty for a tunnel, and on
    /// macOS 27 often the placeholder `02:00:00:00:00:00`.
    pub mac: Vec<u8>,
    /// Each address with its mask (4 or 16 bytes), in the kernel's order.
    pub addrs: Vec<(IpAddr, Vec<u8>)>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl Link {
    pub fn up(&self) -> bool {
        self.flags & l::IFF_UP != 0
    }

    pub fn loopback(&self) -> bool {
        self.flags & l::IFF_LOOPBACK != 0
    }
}

/// One socket address as `x/net/route` reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sock {
    Link { name: String, addr: Vec<u8> },
    V4([u8; 4]),
    V6([u8; 16]),
}

fn bytes<const N: usize>(b: &[u8], off: usize) -> Option<[u8; N]> {
    b.get(off..off + N)?.try_into().ok()
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    bytes(b, off).map(u16::from_ne_bytes)
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    bytes(b, off).map(u32::from_ne_bytes)
}

fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    bytes(b, off).map(i32::from_ne_bytes)
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    bytes(b, off).map(u64::from_ne_bytes)
}

/// `x/net/route`'s `roundup` on Darwin: socket addresses take whole 4-byte
/// words, and an empty one takes one word.
pub fn roundup(len: usize) -> usize {
    if len == 0 { 4 } else { (len + 3) & !3 }
}

/// Copies as much of `src` as fits into the front of `dst`, as Go's `copy`.
fn copy_front(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    dst[..n].copy_from_slice(&src[..n]);
}

/// `parseKernelLinkAddr` on the `sockaddr_dl` that starts `b`: name length,
/// address length and selector length at bytes 5 to 7, then the name and
/// the address. `0xff` in a length means none.
fn link_addr(b: &[u8]) -> Option<Sock> {
    if b.len() < 8 {
        return None;
    }
    let len = |v: u8| if v == 0xff { 0 } else { usize::from(v) };
    let (nlen, alen, slen) = (len(b[5]), len(b[6]), len(b[7]));
    let data = &b[8..];
    if data.len() < nlen + alen + slen {
        return None;
    }
    Some(Sock::Link {
        name: String::from_utf8_lossy(&data[..nlen]).into_owned(),
        addr: data[nlen..nlen + alen].to_vec(),
    })
}

/// `parseInetAddr`: a full `sockaddr_in` or `sockaddr_in6`. A link-local or
/// interface-local IPv6 address carries the interface index in bytes 2-3
/// (the KAME form); Go clears it, so `fe80:4::1` reads `fe80::1`.
fn inet_addr(family: u8, b: &[u8]) -> Option<Sock> {
    if family == l::AF_INET {
        (b.len() >= 16).then(|| Sock::V4(bytes(b, 4).unwrap_or_default()))
    } else {
        let mut ip: [u8; 16] = if b.len() >= 28 {
            bytes(b, 8)?
        } else {
            return None;
        };
        let scoped = (ip[0] == 0xfe && ip[1] & 0xc0 == 0x80)
            || (ip[0] == 0xff && matches!(ip[1] & 0x0f, 0x01 | 0x02));
        if scoped {
            ip[2] = 0;
            ip[3] = 0;
        }
        Some(Sock::V6(ip))
    }
}

/// `parseKernelInetAddr`: a mask in the kernel's short form (family not
/// set, length cut after the last non-zero byte). Returns the length Go
/// moves on by, before rounding.
fn kernel_inet_addr(family: u8, b: &[u8]) -> Option<(usize, Sock)> {
    let mut len = usize::from(*b.first()?);
    if len == 0 || b.len() > roundup(len) {
        len = roundup(len);
    }
    if b.len() < len {
        return None;
    }
    let declared = usize::from(b[0]);
    let sock = if b[0] == 28 {
        Sock::V6(bytes(b, 8)?)
    } else if family == l::AF_INET6 {
        let mut ip = [0u8; 16];
        copy_front(
            &mut ip,
            if len < 9 {
                &b[1..len]
            } else {
                &b[len - 8..len]
            },
        );
        Sock::V6(ip)
    } else if b[0] == 16 {
        Sock::V4(bytes(b, 4)?)
    } else {
        let mut ip = [0u8; 4];
        copy_front(
            &mut ip,
            if len < 5 {
                &b[1..len.max(1)]
            } else {
                &b[len - 4..len]
            },
        );
        Sock::V4(ip)
    };
    Some((declared, sock))
}

/// `parseAddrs`: the socket addresses after a header, one for each bit of
/// `mask`, in slot order. `None` when one cannot be read (Go then drops the
/// message).
fn sockaddrs(mut b: &[u8], mask: i32) -> Option<Vec<Option<Sock>>> {
    let mut out = vec![None; l::RTAX_MAX];
    let mut family = 0u8;
    for (slot, entry) in out.iter_mut().enumerate() {
        if mask & (1 << slot) == 0 {
            continue;
        }
        if b.len() < roundup(0) || slot > l::RTAX_BRD {
            break;
        }
        let step = match b[1] {
            f if f == l::AF_LINK => {
                *entry = Some(link_addr(b)?);
                roundup(usize::from(b[0]))
            }
            f if f == l::AF_INET || f == l::AF_INET6 => {
                family = f;
                *entry = Some(inet_addr(f, b)?);
                roundup(usize::from(b[0]))
            }
            _ => {
                let (len, sock) = kernel_inet_addr(family, b)?;
                *entry = Some(sock);
                if b.len() < roundup(len) {
                    len
                } else {
                    roundup(len)
                }
            }
        };
        b = b.get(step..).unwrap_or_default();
    }
    Some(out)
}

fn parse_link(msg: &[u8]) -> Option<Link> {
    let addrs = sockaddrs(msg.get(l::IFM_HEADER..)?, i32_at(msg, l::IFM_ADDRS)?)?;
    let (name, mac) = match &addrs[l::RTAX_IFP] {
        Some(Sock::Link { name, addr }) => (name.clone(), addr.clone()),
        _ => (String::new(), Vec::new()),
    };
    Some(Link {
        index: u16_at(msg, l::IFM_INDEX)?,
        name,
        flags: i32_at(msg, l::IFM_FLAGS)?,
        mtu: u32_at(msg, l::IFI_MTU)?,
        mac,
        addrs: Vec::new(),
        rx_bytes: u64_at(msg, l::IFI_IBYTES)?,
        tx_bytes: u64_at(msg, l::IFI_OBYTES)?,
        rx_packets: u64_at(msg, l::IFI_IPACKETS)?,
        tx_packets: u64_at(msg, l::IFI_OPACKETS)?,
    })
}

/// Go's `interfaceAddrTable` for one `RTM_NEWADDR`: the address and its
/// mask, kept only when both are IP addresses.
fn parse_addr(msg: &[u8]) -> Option<(u16, IpAddr, Vec<u8>)> {
    let addrs = sockaddrs(msg.get(l::IFAM_HEADER..)?, i32_at(msg, l::IFAM_ADDRS)?)?;
    let mask = match &addrs[l::RTAX_NETMASK] {
        Some(Sock::V4(m)) => m.to_vec(),
        Some(Sock::V6(m)) => m.to_vec(),
        _ => return None,
    };
    let ip = match &addrs[l::RTAX_IFA] {
        Some(Sock::V4(ip)) => IpAddr::V4(Ipv4Addr::from(*ip)),
        Some(Sock::V6(ip)) => IpAddr::V6(Ipv6Addr::from(*ip)),
        _ => return None,
    };
    Some((u16_at(msg, l::IFAM_INDEX)?, ip, mask))
}

/// Every interface in the dump, in the kernel's (index) order, each with
/// its addresses. Messages of other types (multicast memberships) and
/// messages that cannot be read are skipped.
pub fn parse_interface_table(buf: &[u8]) -> Vec<Link> {
    let mut links: Vec<Link> = Vec::new();
    let mut off = 0;
    while buf.len() - off > 4 {
        let len = usize::from(u16_at(buf, off).unwrap_or(0));
        if len < 4 || off + len > buf.len() {
            break;
        }
        let msg = &buf[off..off + len];
        off += len;
        match msg[3] {
            t if t == l::RTM_IFINFO2 => links.extend(parse_link(msg)),
            t if t == l::RTM_NEWADDR => {
                let Some((index, ip, mask)) = parse_addr(msg) else {
                    continue;
                };
                if let Some(link) = links.iter_mut().rev().find(|link| link.index == index) {
                    link.addrs.push((ip, mask));
                }
            }
            _ => {}
        }
    }
    links
}

/// One entry of the `ifmibdata` dump: an interface's name and its whole
/// 64-bit counters.
struct IfData {
    name: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

fn parse_entry(entry: &[u8; l::IFMD_SIZE]) -> Option<IfData> {
    let name = entry.get(l::IFMD_NAME..l::IFMD_NAME + l::IFMD_NAME_LEN)?;
    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
    if name.is_empty() {
        return None;
    }
    Some(IfData {
        name: String::from_utf8_lossy(name).into_owned(),
        rx_bytes: u64_at(entry, l::IFMD_IBYTES)?,
        tx_bytes: u64_at(entry, l::IFMD_OBYTES)?,
        rx_packets: u64_at(entry, l::IFMD_IPACKETS)?,
        tx_packets: u64_at(entry, l::IFMD_OPACKETS)?,
    })
}

/// Every named entry of the `net.link.generic.ifalldata` dump. The kernel
/// writes an entry with no name for an interface still being attached;
/// those are skipped.
fn parse_interface_data(buf: &[u8]) -> Vec<IfData> {
    let (entries, _) = buf.as_chunks::<{ l::IFMD_SIZE }>();
    entries.iter().filter_map(parse_entry).collect()
}

/// The interfaces in an interface table dump, each with the whole counters
/// of the entry of the same name in a counter dump when there is one. The
/// interface table's own byte counters are what the kernel gives a program
/// that is not part of macOS: the low 32 bits, rounded down to 1 KiB, so
/// they wrap every 4 GiB. A link with no counter entry keeps them.
pub fn links_from(table: &[u8], data: Option<&[u8]>) -> Vec<Link> {
    let mut links = parse_interface_table(table);
    let data = data.map(parse_interface_data).unwrap_or_default();
    for link in &mut links {
        if let Some(full) = data.iter().find(|d| d.name == link.name) {
            link.rx_bytes = full.rx_bytes;
            link.tx_bytes = full.tx_bytes;
            link.rx_packets = full.rx_packets;
            link.tx_packets = full.tx_packets;
        }
    }
    links
}

/// The interfaces of this host, with whole counters. When the counter
/// dump cannot be read, the interface table's counters stay, and a warning
/// is logged once.
pub fn links() -> std::io::Result<Vec<Link>> {
    static WARNED: std::sync::Once = std::sync::Once::new();
    let table = labtether_agent_macos_sys::interface_table()?;
    let data = labtether_agent_macos_sys::interface_data()
        .inspect_err(|error| {
            WARNED.call_once(|| {
                log::warn!(
                    "cannot read interface counters (net.link.generic.ifalldata): {error}; byte counts wrap at 4 GiB"
                );
            });
        })
        .ok();
    Ok(links_from(&table, data.as_deref()))
}
