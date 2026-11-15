//! The disk, interface and process list readers against captured text and
//! made-up trees. Each test names the fault it catches. Host names, users
//! and addresses are made up.

use std::io;
use std::net::IpAddr;
use std::path::Path;

use super::TempDir;
use crate::linux::disk::Capacity;
use crate::linux::interfaces::{InterfaceRow, rows};
use crate::linux::mounts::{
    MountListError, mount_list_with, parse_mounts, saturating_bytes, usage,
};
use crate::linux::netid::Nic;
use crate::linux::netlink::{parse_address, parse_link};

// Captured from a Debian 13 VM, trimmed; the last lines are made up to hit
// each rule once.
const PROC_MOUNTS: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime,size=8148540k 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime 0 0
/dev/sda15 /boot/efi vfat rw,relatime,fmask=0077 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,relatime 0 0
# a comment
none /mnt/none ext4 rw 0 0
short line
nas01:/tank /mnt/tank nfs4 rw,relatime 0 0
/dev/sdb1 /mnt/backup\\040disk ext4 rw 0 0
overlay /srv/merged overlay rw,relatime 0 0
portal /run/user/1000/doc fuse.portal rw 0 0
/dev/sda1 /srv/bind ext4 rw,relatime 0 0
";

// Fault: a virtual filesystem, a `/sys` or `/proc` mount, a `none` device or
// a Docker overlay is listed; the order changes; bind mounts are merged; or
// the `\040` escape is undone (Go keeps it, so `statfs` then fails).
#[test]
fn mounts_keep_go_order_and_skip_rules() {
    let points: Vec<String> = parse_mounts(PROC_MOUNTS)
        .into_iter()
        .map(|entry| format!("{} {} {}", entry.device, entry.mount_point, entry.fs_type))
        .collect();
    assert_eq!(
        points,
        [
            "/dev/sda1 / ext4",
            "/dev/sda15 /boot/efi vfat",
            "nas01:/tank /mnt/tank nfs4",
            "/dev/sdb1 /mnt/backup\\040disk ext4",
            "overlay /srv/merged overlay",
            "/dev/sda1 /srv/bind ext4",
        ]
    );
}

// Fault: used space is counted from the blocks free to users (Go counts it
// from all free blocks, so the root reserve is used), the percent is not
// used over total, or the block product overflows instead of saturating.
#[test]
fn mount_usage_counts_the_root_reserve_as_used() {
    let entry = &parse_mounts("/dev/sda1 / ext4 rw 0 0\n")[0];
    let capacity = Capacity {
        blocks: 1000,
        available_blocks: 300,
        free_blocks: 350,
        block_size: 4096,
    };
    let row = usage(entry, &capacity);
    assert_eq!(row.total, 4_096_000);
    assert_eq!(row.used, 650 * 4096);
    assert_eq!(row.available, 300 * 4096);
    assert_eq!(row.use_pct, 65.0);
    let unknown = usage(
        entry,
        &Capacity {
            block_size: -1,
            ..capacity
        },
    );
    assert_eq!((unknown.total, unknown.used, unknown.use_pct), (0, 0, 0.0));
    assert_eq!(saturating_bytes(u64::MAX, 2), u64::MAX);
    assert_eq!(saturating_bytes(10, 0), 0);
}

// Fault: a failed `statfs` stops the list or is listed with zeros (Go skips
// it), or an unreadable `/proc/mounts` starts a process or returns an empty
// list without saying why (the `df -kP` gap must stay visible).
#[test]
fn mount_list_skips_failed_statfs_and_reports_the_df_gap() {
    let dir = TempDir::new("mounts");
    let path = dir.write(
        "mounts",
        "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /gone ext4 rw 0 0\n",
    );
    let stat = |point: &Path| {
        if point == Path::new("/") {
            Ok(Capacity {
                blocks: 10,
                available_blocks: 5,
                free_blocks: 5,
                block_size: 1024,
            })
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    };
    let list = mount_list_with(&path, stat).unwrap();
    assert_eq!(list.mounts.len(), 1);
    assert_eq!(list.mounts[0].mount_point, "/");
    assert_eq!(list.skipped.len(), 1);
    assert_eq!(list.skipped[0].0, "/gone");

    let missing = mount_list_with(&dir.0.join("no-such-file"), stat).unwrap_err();
    assert!(matches!(missing, MountListError::NoDfFallback(_)));
    assert!(missing.to_string().contains("no df fallback"), "{missing}");
}

fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(u16::try_from(4 + value.len()).unwrap()).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn link(link_type: u16, index: i32, flags: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0u8, 0];
    out.extend_from_slice(&link_type.to_ne_bytes());
    out.extend_from_slice(&index.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    attrs.iter().for_each(|a| out.extend_from_slice(a));
    out
}

// Fault: the MTU is not read, a tunnel's IPv4 end point is shown as its
// MAC (Go's `newLink` drops it), or the prefix length is lost.
#[test]
fn netlink_reads_mtu_tunnel_rule_and_prefix() {
    let mac = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
    let ether = link(
        1,
        2,
        0x1,
        &[
            attr(3, b"ens18\0"),
            attr(1, &mac),
            attr(4, &1500u32.to_ne_bytes()),
        ],
    );
    let (index, nic) = parse_link(&ether).unwrap();
    assert_eq!(
        (index, nic.name.as_str(), nic.up, nic.mtu),
        (2, "ens18", true, 1500)
    );
    assert_eq!(nic.mac, mac);
    let sit = link(
        776,
        5,
        0,
        &[
            attr(3, b"sit1\0"),
            attr(1, &[192, 0, 2, 7]),
            attr(4, &1480u32.to_ne_bytes()),
        ],
    );
    let (_, tunnel) = parse_link(&sit).unwrap();
    assert!(tunnel.mac.is_empty(), "{:?}", tunnel.mac);
    assert!(!tunnel.up);

    let mut v4 = vec![2u8, 24, 0, 0];
    v4.extend_from_slice(&2i32.to_ne_bytes());
    v4.extend(attr(1, &[192, 0, 2, 255]));
    v4.extend(attr(2, &[192, 0, 2, 10]));
    let (index, ip, prefix) = parse_address(&v4).unwrap();
    assert_eq!(
        (index, ip, prefix),
        (2, "192.0.2.10".parse::<IpAddr>().unwrap(), 24)
    );
}

// Fault: loopback is listed, the order changes, a missing counter file
// fails the row (Go reads it as 0), the state ignores `IFF_UP`, or the MAC
// or address text differs from Go's.
#[test]
fn interface_rows_follow_go() {
    let dir = TempDir::new("net");
    for (file, value) in [
        ("rx_bytes", "1200\n"),
        ("tx_bytes", "3400\n"),
        ("rx_packets", "12\n"),
    ] {
        dir.write(&format!("ens18/statistics/{file}"), value);
    }
    dir.write("lo/statistics/rx_bytes", "99\n");
    let ip = |text: &str| text.parse::<IpAddr>().unwrap();
    let nics = [
        Nic {
            name: "lo".into(),
            up: true,
            loopback: true,
            ips: vec![ip("127.0.0.1")],
            prefixes: vec![8],
            mtu: 65536,
            ..Nic::default()
        },
        Nic {
            name: "ens18".into(),
            mac: vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a],
            up: true,
            ips: vec![ip("192.0.2.10"), ip("2001:db8:0:0:0:0:0:10")],
            prefixes: vec![24, 64],
            mtu: 1500,
            ..Nic::default()
        },
        Nic {
            name: "wg0".into(),
            mtu: 1420,
            ..Nic::default()
        },
    ];
    let got = rows(&nics, &dir.0);
    assert_eq!(
        got,
        [
            InterfaceRow {
                name: "ens18".into(),
                state: "up",
                mac: "00:00:5e:00:53:0a".into(),
                mtu: 1500,
                ips: vec!["192.0.2.10/24".into(), "2001:db8::10/64".into()],
                rx_bytes: 1200,
                tx_bytes: 3400,
                rx_packets: 12,
                tx_packets: 0,
            },
            InterfaceRow {
                name: "wg0".into(),
                state: "down",
                mac: String::new(),
                mtu: 1420,
                ips: Vec::new(),
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
            },
        ]
    );
}
