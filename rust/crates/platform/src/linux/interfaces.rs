//! The interface list behind `network.list`, ported from Go's
//! `collectNetInterfaces` (`internal/agentcore/sysconfig/network_handler.go`)
//! and `ReadIfaceStats` (`network_stats_linux.go`): the kernel's interfaces
//! in index order without loopback, each with its state, MAC, MTU,
//! addresses as `address/prefix`, and the four counters from
//! `/sys/class/net/<name>/statistics/`.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::netid::Nic;
use super::netlink;

/// One row, as Go fills `protocol.NetInterface`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceRow {
    pub name: String,
    /// `up` when the kernel's `IFF_UP` flag is set, else `down`.
    pub state: &'static str,
    /// Lowercase hex bytes joined by `:`, empty without a hardware address.
    pub mac: String,
    pub mtu: i64,
    pub ips: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Go's `HardwareAddr.String`.
pub fn mac_text(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Go's `IPNet.String` for an interface address: `address/prefix`.
pub fn address_text(ip: IpAddr, prefix: u8) -> String {
    format!("{ip}/{prefix}")
}

/// Go's `readUint64File`: the trimmed number, or 0 when the file cannot be
/// read or parsed.
pub fn parse_counter(text: Option<String>) -> u64 {
    text.and_then(|text| text.trim().parse().ok()).unwrap_or(0)
}

/// The four counters of `name` under `sys_class_net`; a missing file reads
/// as 0, as in Go.
pub fn counters(sys_class_net: &Path, name: &str) -> [u64; 4] {
    let base = sys_class_net.join(name).join("statistics");
    ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets"]
        .map(|file| parse_counter(std::fs::read_to_string(base.join(file)).ok()))
}

/// Rows for `nics` in their order, loopback left out.
pub fn rows(nics: &[Nic], sys_class_net: &Path) -> Vec<InterfaceRow> {
    nics.iter()
        .filter(|nic| !nic.loopback)
        .map(|nic| {
            let [rx_bytes, tx_bytes, rx_packets, tx_packets] = counters(sys_class_net, &nic.name);
            InterfaceRow {
                name: nic.name.clone(),
                state: if nic.up { "up" } else { "down" },
                mac: mac_text(&nic.mac),
                mtu: i64::from(nic.mtu),
                ips: nic
                    .ips
                    .iter()
                    .zip(&nic.prefixes)
                    .map(|(ip, prefix)| address_text(*ip, *prefix))
                    .collect(),
                rx_bytes,
                tx_bytes,
                rx_packets,
                tx_packets,
            }
        })
        .collect()
}

/// The interface list of this host.
pub fn interface_rows() -> io::Result<Vec<InterfaceRow>> {
    Ok(rows(
        &netlink::interface_list()?,
        &PathBuf::from("/sys/class/net"),
    ))
}
