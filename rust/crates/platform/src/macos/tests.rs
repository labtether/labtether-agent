//! macOS readers on made-up input: the interface table built byte by byte
//! from the C layout, mount table rows, tick and page counts. Each test
//! names the fault it catches. Values are made up (documentation
//! addresses, `nas01`).

use std::net::IpAddr;

use labtether_agent_macos_sys::layout as l;
use labtether_agent_macos_sys::{CpuTicks, FsStat, VmCounts};

use super::disk::Capacity;
use super::host::{self, HostFacts};
use super::interfaces::{self, address_text};
use super::mounts::{self, df_row};
use super::netid;
use super::route::{links_from, parse_interface_table, roundup};
use super::sampler::{
    cpu_busy_percent, disk_used_percent, memory_used_percent, net_totals, rate_per_sec,
};

fn pad(mut sa: Vec<u8>) -> Vec<u8> {
    sa.resize(roundup(sa.len().max(usize::from(sa[0]))), 0);
    sa
}

fn sockaddr_dl(index: u16, name: &str, mac: &[u8]) -> Vec<u8> {
    let mut sa = vec![0, l::AF_LINK];
    sa.extend(index.to_ne_bytes());
    sa.extend([6, name.len() as u8, mac.len() as u8, 0]);
    sa.extend(name.as_bytes());
    sa.extend(mac);
    sa.resize(sa.len().max(20), 0);
    sa[0] = sa.len() as u8;
    pad(sa)
}

fn sockaddr_in(ip: [u8; 4]) -> Vec<u8> {
    let mut sa = vec![16, l::AF_INET, 0, 0];
    sa.extend(ip);
    sa.resize(16, 0);
    sa
}

fn sockaddr_in6(ip: [u8; 16]) -> Vec<u8> {
    let mut sa = vec![28, l::AF_INET6, 0, 0, 0, 0, 0, 0];
    sa.extend(ip);
    sa.resize(28, 0);
    sa
}

fn message(kind: u8, header: usize, fill: impl FnOnce(&mut Vec<u8>), addrs: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = vec![0u8; header];
    msg[2] = 5;
    msg[3] = kind;
    fill(&mut msg);
    for sa in addrs {
        msg.extend(sa);
    }
    let len = msg.len() as u16;
    msg[..2].copy_from_slice(&len.to_ne_bytes());
    msg
}

#[derive(Clone, Copy)]
struct Counters {
    rx: u64,
    tx: u64,
    rx_packets: u64,
    tx_packets: u64,
}

fn link_message(index: u16, name: &str, flags: i32, mtu: u32, mac: &[u8], c: Counters) -> Vec<u8> {
    let put = |msg: &mut Vec<u8>, off: usize, bytes: &[u8]| {
        msg[off..off + bytes.len()].copy_from_slice(bytes)
    };
    message(
        l::RTM_IFINFO2,
        l::IFM_HEADER,
        |msg| {
            put(msg, l::IFM_ADDRS, &(1i32 << l::RTAX_IFP).to_ne_bytes());
            put(msg, l::IFM_FLAGS, &flags.to_ne_bytes());
            put(msg, l::IFM_INDEX, &index.to_ne_bytes());
            put(msg, l::IFI_MTU, &mtu.to_ne_bytes());
            put(msg, l::IFI_IBYTES, &c.rx.to_ne_bytes());
            put(msg, l::IFI_OBYTES, &c.tx.to_ne_bytes());
            put(msg, l::IFI_IPACKETS, &c.rx_packets.to_ne_bytes());
            put(msg, l::IFI_OPACKETS, &c.tx_packets.to_ne_bytes());
        },
        &[sockaddr_dl(index, name, mac)],
    )
}

/// An address message with netmask, address and (for IPv4) broadcast.
fn addr_message(index: u16, mask: Vec<u8>, ifa: Vec<u8>, brd: Option<Vec<u8>>) -> Vec<u8> {
    let mut bits = 1i32 << l::RTAX_NETMASK | 1 << l::RTAX_IFA;
    let mut addrs = vec![mask, ifa];
    if let Some(brd) = brd {
        bits |= 1 << l::RTAX_BRD;
        addrs.push(brd);
    }
    message(
        l::RTM_NEWADDR,
        l::IFAM_HEADER,
        |msg| {
            msg[l::IFAM_ADDRS..l::IFAM_ADDRS + 4].copy_from_slice(&bits.to_ne_bytes());
            msg[l::IFAM_INDEX..l::IFAM_INDEX + 2].copy_from_slice(&index.to_ne_bytes());
        },
        &addrs,
    )
}

const UP: i32 = l::IFF_UP;
const MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a];
const PLACEHOLDER: [u8; 6] = [2, 0, 0, 0, 0, 0];
const FIVE_GIB: u64 = 5 * 1024 * 1024 * 1024;

fn table() -> Vec<u8> {
    let zero = || Counters {
        rx: 0,
        tx: 0,
        rx_packets: 0,
        tx_packets: 0,
    };
    let mut fe80 = [0u8; 16];
    fe80[..4].copy_from_slice(&[0xfe, 0x80, 0x00, 0x04]); // KAME scope: index 4
    fe80[15] = 1;
    let mut doc6 = [0u8; 16];
    doc6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    doc6[15] = 0x10;
    let mut mask64 = [0u8; 16];
    mask64[..8].fill(0xff);
    let mut buf = Vec::new();
    buf.extend(link_message(
        1,
        "lo0",
        UP | l::IFF_LOOPBACK,
        16384,
        &[],
        zero(),
    ));
    buf.extend(addr_message(
        1,
        vec![8, 0, 0, 0, 255, 0, 0, 0],
        sockaddr_in([127, 0, 0, 1]),
        None,
    ));
    buf.extend(link_message(
        4,
        "en0",
        UP,
        1500,
        &MAC,
        Counters {
            rx: FIVE_GIB,
            tx: 7,
            rx_packets: 3,
            tx_packets: 4,
        },
    ));
    // A multicast membership message (RTM_NEWMADDR2) the parser must skip.
    buf.extend(message(0x14, 20, |_| {}, &[]));
    // IPv4 netmask in the kernel's short form: family not set, length 7.
    buf.extend(addr_message(
        4,
        vec![7, 0, 0, 0, 255, 255, 255, 0],
        sockaddr_in([192, 0, 2, 10]),
        Some(sockaddr_in([192, 0, 2, 255])),
    ));
    buf.extend(addr_message(
        4,
        sockaddr_in6(mask64),
        sockaddr_in6(fe80),
        None,
    ));
    buf.extend(addr_message(
        4,
        sockaddr_in6(mask64),
        sockaddr_in6(doc6),
        None,
    ));
    buf.extend(link_message(9, "en1", 0, 1500, &PLACEHOLDER, zero()));
    buf.extend(link_message(12, "utun3", UP, 1380, &[], zero()));
    buf
}

// Faults: a counter read at the wrong offset or as 32 bits (5 GiB wraps), a
// flag or MTU misread, a link-local address keeping its KAME scope bytes
// (`fe80:4::1`), the short-form netmask misread, addresses attached to the
// wrong interface, or an unknown message type stopping the parse.
#[test]
fn interface_table_reads_like_go_net_interfaces() {
    let links = parse_interface_table(&table());
    let names: Vec<&str> = links.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(names, ["lo0", "en0", "en1", "utun3"]);
    let en0 = &links[1];
    assert_eq!(
        (en0.index, en0.mtu, en0.up(), en0.loopback()),
        (4, 1500, true, false)
    );
    assert_eq!(
        (en0.rx_bytes, en0.tx_bytes, en0.rx_packets, en0.tx_packets),
        (FIVE_GIB, 7, 3, 4)
    );
    assert_eq!(en0.mac, MAC);
    let ips: Vec<String> = en0
        .addrs
        .iter()
        .map(|(ip, m)| address_text(*ip, m))
        .collect();
    assert_eq!(ips, ["192.0.2.10/24", "fe80::1/64", "2001:db8::10/64"]);
    assert!(links[0].loopback());
    assert_eq!(
        address_text(links[0].addrs[0].0, &links[0].addrs[0].1),
        "127.0.0.1/8"
    );
}

// Faults: loopback listed, a placeholder MAC sent as real (Wake-on-LAN to
// 02:00:00:00:00:00 reaches nothing), a down interface shown up, or the
// heartbeat's MAC taken from a placeholder.
#[test]
fn interface_rows_drop_loopback_and_placeholder_macs() {
    let links = parse_interface_table(&table());
    let rows = interfaces::rows(&links);
    let view: Vec<(&str, &str, &str, usize)> = rows
        .iter()
        .map(|r| (r.name.as_str(), r.state, r.mac.as_str(), r.ips.len()))
        .collect();
    assert_eq!(
        view,
        [
            ("en0", "up", "00:00:5e:00:53:0a", 3),
            ("en1", "down", "", 0),
            ("utun3", "up", "", 0)
        ]
    );
    let route_ip: Option<IpAddr> = Some("192.0.2.10".parse().unwrap());
    let nics = interfaces::nics(&links);
    assert_eq!(netid::primary_mac(&nics, route_ip), "00:00:5e:00:53:0a");
    assert_eq!(netid::primary_ip(&nics, route_ip), "192.0.2.10");
    let mut redacted = links.clone();
    redacted[1].mac = PLACEHOLDER.to_vec();
    assert_eq!(
        netid::primary_mac(&interfaces::nics(&redacted), route_ip),
        ""
    );
}

// Faults: a mask that is not a prefix printed as a length, or an address
// whose mask does not fit printed at all (Go prints `<nil>`).
#[test]
fn address_text_follows_go_ipnet_string() {
    let v4: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(address_text(v4, &[255, 0, 255, 0]), "192.0.2.10/ff00ff00");
    assert_eq!(address_text(v6, &[255, 255, 255, 0]), "<nil>");
    let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
    let mut mask = [0xffu8; 16];
    mask[15] = 0;
    assert_eq!(address_text(mapped, &mask), "192.0.2.10/24");
}

/// A byte counter as the interface table gives it to a program that is not
/// part of macOS: the low 32 bits, rounded down to 1 KiB (XNU
/// `ALIGN_BYTES` in `bsd/net/rtsock.c`; seen on macOS 27.2.1).
fn cut(bytes: u64) -> u64 {
    u64::from(bytes as u32) & !1023
}

/// One `ifmibdata` entry of the `net.link.generic.ifalldata` dump.
fn ifmib_entry(name: &str, c: Counters) -> Vec<u8> {
    let mut entry = vec![0u8; l::IFMD_SIZE];
    entry[l::IFMD_NAME..l::IFMD_NAME + name.len()].copy_from_slice(name.as_bytes());
    for (off, value) in [
        (l::IFMD_IBYTES, c.rx),
        (l::IFMD_OBYTES, c.tx),
        (l::IFMD_IPACKETS, c.rx_packets),
        (l::IFMD_OPACKETS, c.tx_packets),
    ] {
        entry[off..off + 8].copy_from_slice(&value.to_ne_bytes());
    }
    entry
}

/// The interface table (byte counters cut as the kernel cuts them) and the
/// counter dump (whole counters) for loopback and en0 at the given
/// counters, plus a tunnel that has no counter entry.
fn dumps(lo0: Counters, en0: Counters) -> (Vec<u8>, Vec<u8>) {
    let seen = |c: Counters| Counters {
        rx: cut(c.rx),
        tx: cut(c.tx),
        ..c
    };
    let mut table = link_message(1, "lo0", UP | l::IFF_LOOPBACK, 16384, &[], seen(lo0));
    table.extend(link_message(4, "en0", UP, 1500, &MAC, seen(en0)));
    let tunnel = Counters {
        rx: 5000,
        tx: 6000,
        rx_packets: 7,
        tx_packets: 8,
    };
    table.extend(link_message(12, "utun3", UP, 1380, &[], tunnel));
    let mut data = ifmib_entry("lo0", lo0);
    data.extend(vec![0u8; l::IFMD_SIZE]); // an interface still attaching: no name
    data.extend(ifmib_entry("en0", en0));
    (table, data)
}

// Fault (a Mac on 2026-11-16): `network.list` gave en0's received bytes as
// 512,438,272 where netstat showed 52,052,047,300, because the counters
// came from the interface table, which the kernel cuts to 32 bits for this
// agent. Also: an entry with no name stopping the read of the entries
// after it, or a link with no counter entry losing its counters.
#[test]
fn network_rows_carry_whole_counters_past_4_gib() {
    let lo0 = Counters {
        rx: 99_846_280_428,
        tx: 99_846_280_428,
        rx_packets: 9,
        tx_packets: 9,
    };
    let en0 = Counters {
        rx: 52_052_047_300,
        tx: 8_073_499_033,
        rx_packets: 65_892_853,
        tx_packets: 12_864_300,
    };
    let (table, data) = dumps(lo0, en0);
    let rows = interfaces::rows(&links_from(&table, Some(&data)));
    let view: Vec<(&str, u64, u64, u64, u64)> = rows
        .iter()
        .map(|r| {
            (
                r.name.as_str(),
                r.rx_bytes,
                r.tx_bytes,
                r.rx_packets,
                r.tx_packets,
            )
        })
        .collect();
    assert_eq!(
        view,
        [
            ("en0", 52_052_047_300, 8_073_499_033, 65_892_853, 12_864_300),
            ("utun3", 5000, 6000, 7, 8)
        ]
    );
}

// Fault: each time the summed counter passed a multiple of 4 GiB it went
// down, so that sample's rate was 0; at 10 Gbit/s the cut counter wraps
// every 3.4 s, so most samples were wrong. Two samples one second apart
// across 4 GiB must give the bytes that passed.
#[test]
fn telemetry_rate_is_right_across_4_gib() {
    let total = |en0_rx: u64| {
        let lo0 = Counters {
            rx: 1000,
            tx: 1000,
            rx_packets: 1,
            tx_packets: 1,
        };
        let en0 = Counters {
            rx: en0_rx,
            tx: 10,
            rx_packets: 1,
            tx_packets: 1,
        };
        let (table, data) = dumps(lo0, en0);
        net_totals(&links_from(&table, Some(&data))).0 as f64
    };
    let rate = rate_per_sec(total(4_294_000_000), total(4_296_000_000), 1.0);
    assert_eq!(rate, 2_000_000.0);
}

fn fs(from: &str, on: &str, blocks: u64, bfree: u64, bavail: u64, bsize: u32) -> FsStat {
    FsStat {
        from: from.into(),
        on: on.into(),
        fs_type: "apfs".into(),
        flags: 0,
        blocks,
        bfree,
        bavail,
        bsize,
    }
}

// Faults: used space taken from the container (`f_blocks - f_bfree`)
// instead of the volume's own share, sizes not in df's 1024-byte units, the
// percent rounded down or to nearest instead of up, a 512-byte block size
// multiplied instead of divided, or a failed `getattrlist` dropping the
// mount instead of falling back.
#[test]
fn df_rows_match_apple_df() {
    // 4 KiB blocks: 1000 total, 400 free in the container, 300 available.
    let data = fs("/dev/disk3s5", "/System/Volumes/Data", 1000, 400, 300, 4096);
    let row = df_row(&data, || Some(250 * 4096)).unwrap();
    assert_eq!(
        (row.total, row.used, row.available),
        (4_096_000, 1_024_000, 1_228_800)
    );
    assert_eq!(row.use_pct, 46.0); // 250 / 550 = 45.45..., rounded up
    assert_eq!(row.fs_type, "");
    let fallback = df_row(&data, || None).unwrap();
    assert_eq!((fallback.used, fallback.use_pct), (2_457_600, 67.0)); // 600 / 900
    let small = df_row(
        &fs("/dev/disk9", "/Volumes/Old", 2000, 1000, 1000, 512),
        || None,
    )
    .unwrap();
    assert_eq!(
        (small.total, small.used, small.use_pct),
        (1_024_000, 512_000, 50.0)
    );
    let full = df_row(&fs("/dev/disk9", "/Volumes/Full", 10, 0, 0, 4096), || {
        Some(40960)
    })
    .unwrap();
    assert_eq!(full.use_pct, 100.0);
    assert_eq!(mounts::capacity_percent(0, 0), 100.0);
}

// Faults: devfs or an automounter map (0 blocks) listed, a system volume
// (Preboot, VM, Update, Recovery) listed, the data volume or `/` hidden, or
// the table's order changed.
#[test]
fn mount_list_keeps_go_rules_and_order() {
    let table = [
        fs("/dev/disk3s1s1", "/", 1000, 400, 300, 4096),
        fs("devfs", "/dev", 1, 0, 0, 512),
        fs("/dev/disk3s6", "/System/Volumes/VM", 1000, 400, 300, 4096),
        fs(
            "/dev/disk3s2",
            "/System/Volumes/Preboot",
            1000,
            400,
            300,
            4096,
        ),
        fs("/dev/disk3s5", "/System/Volumes/Data", 1000, 400, 300, 4096),
        fs("map auto_home", "/System/Volumes/Data/home", 0, 0, 0, 4096),
        fs("/dev/disk2s1", "/Volumes/Recovery", 1000, 400, 300, 4096),
        fs(
            "/dev/disk5s1",
            "/Volumes/nas01 backup",
            1000,
            400,
            300,
            4096,
        ),
    ];
    let list = mounts::mount_list_from(&table, |_| Err(std::io::Error::other("no")));
    let points: Vec<&str> = list.mounts.iter().map(|m| m.mount_point.as_str()).collect();
    assert_eq!(
        points,
        ["/", "/System/Volumes/Data", "/Volumes/nas01 backup"]
    );
    assert!(list.skipped.is_empty());
}

fn ticks(user: u32, system: u32, idle: u32, nice: u32) -> CpuTicks {
    CpuTicks {
        user,
        system,
        idle,
        nice,
    }
}

// Faults: idle counted as busy, nice left out of busy, the percent taken
// over the whole uptime instead of the interval, or gopsutil's edge rules
// lost (no busy change is 0, busy without total change is 100).
#[test]
fn cpu_percent_follows_gopsutil_calculate_busy() {
    let before = ticks(1000, 500, 8000, 100);
    let after = ticks(1100, 550, 8300, 150);
    let percent = cpu_busy_percent(before, after, 100.0);
    assert!((percent - 40.0).abs() < 1e-9, "{percent}"); // 200 busy of 500
    assert_eq!(cpu_busy_percent(after, after, 100.0), 0.0);
    assert_eq!(
        cpu_busy_percent(before, ticks(1100, 500, 7900, 100), 100.0),
        100.0
    );
}

// Faults: memory counts free pages only (inactive pages are available to
// gopsutil), the total taken in bytes instead of pages, or disk usage
// measured against `f_blocks` instead of used plus available.
#[test]
fn memory_and_disk_percent_follow_gopsutil() {
    let counts = VmCounts {
        free: 100,
        active: 400,
        inactive: 300,
        wire: 200,
    };
    let percent = memory_used_percent(1000 * 16384, 16384, counts);
    assert!((percent - 60.0).abs() < 1e-9, "{percent}");
    let root = Capacity {
        blocks: 1000,
        available_blocks: 300,
        free_blocks: 400,
        block_size: 4096,
    };
    assert!((disk_used_percent(&root) - 600.0 / 900.0 * 100.0).abs() < 1e-9);
    assert_eq!(disk_used_percent(&Capacity::default()), 0.0);
}

// Faults: macOS named `darwin` on the device page, the pretty name built
// without the version, a host ID in upper case (ioreg's form, which Go
// lowercases), an Intel clock left in Hz, or a CPU count of 0 sent.
#[test]
fn host_keys_follow_gopsutil_and_apply_macos_name() {
    let facts = HostFacts {
        os_type: Some("Darwin".into()),
        product_version: Some("27.2.1".into()),
        os_release: Some("27.2.0".into()),
        machine: Some("arm64".into()),
        host_uuid: Some([0xAB; 16]),
        cpu_brand: Some("Apple M4".into()),
        cpu_vendor: None,
        physical_cpus: Some(10),
        logical_cpus: Some(0),
        cpu_hz: Some(2_600_000_000),
    };
    let os = host::os_metadata(&facts);
    assert_eq!(os["os_name"], "macOS");
    assert_eq!(os["os_pretty_name"], "macOS 27.2.1");
    assert_eq!(
        (os["os_version"].as_str(), os["kernel_version"].as_str()),
        ("27.2.1", "27.2.0")
    );
    assert_eq!(os["host_id"], "abababab-abab-abab-abab-abababababab");
    let cpu = host::cpu_metadata(&facts);
    assert_eq!(cpu["cpu_max_mhz"], "2600");
    assert_eq!(cpu["cpu_cores_physical"], "10");
    assert!(!cpu.contains_key("cpu_threads_logical") && !cpu.contains_key("cpu_vendor"));
    let missing = host::os_metadata(&HostFacts::default());
    assert!(missing.is_empty(), "{missing:?}");
}
