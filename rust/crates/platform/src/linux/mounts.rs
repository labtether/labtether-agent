//! The mount list behind `disk.list`, ported from Go's `collectMountsLinux`
//! and `StatfsMountPoint` (`internal/agentcore/system/disk.go`,
//! `disk_statfs_unix.go`): `/proc/mounts` in file order, virtual
//! filesystems left out, then `statfs` of each mount point.
//!
//! Go reads mount points as `/proc/mounts` writes them, without undoing the
//! kernel's `\040` escapes, so `statfs` fails for a mount point with a space
//! and the mount is left out. This port does the same.
//!
//! When `/proc/mounts` cannot be read, Go runs `df -kP` instead. This agent
//! runs no outside commands yet, so that case returns
//! [`MountListError::NoDfFallback`].

use std::io;
use std::path::Path;

use super::disk::{self, Capacity};

/// Go's `VirtualFSTypes`: filesystems that are not disks.
pub const VIRTUAL_FS_TYPES: [&str; 21] = [
    "proc",
    "sysfs",
    "devtmpfs",
    "tmpfs",
    "devpts",
    "securityfs",
    "cgroup",
    "cgroup2",
    "pstore",
    "debugfs",
    "tracefs",
    "hugetlbfs",
    "mqueue",
    "binfmt_misc",
    "autofs",
    "configfs",
    "efivarfs",
    "fusectl",
    "fuse.lnk",
    "fuse.portal",
    "fuse.gvfsd-fuse",
];

/// One `/proc/mounts` line the disk list keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
}

/// One mount with its space, in bytes, as Go fills `protocol.MountInfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct MountUsage {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub use_pct: f64,
}

/// The mounts, and the mount points whose `statfs` failed (Go logs and
/// skips each one).
#[derive(Debug, Default)]
pub struct MountList {
    pub mounts: Vec<MountUsage>,
    pub skipped: Vec<(String, io::Error)>,
}

/// Why there is no mount list.
#[derive(Debug, thiserror::Error)]
pub enum MountListError {
    /// Go falls back to `df -kP` here; this agent has no such fallback.
    #[error("cannot read /proc/mounts ({0}); this agent has no df fallback yet")]
    NoDfFallback(io::Error),
}

/// The lines Go keeps, in file order: at least three fields, not a virtual
/// type, device not `none`, not under `/sys` or `/proc`, not a Docker
/// overlay under `/var/lib/docker`.
pub fn parse_mounts(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [device, mount_point, fs_type, ..] = fields[..] else {
            continue;
        };
        if VIRTUAL_FS_TYPES.contains(&fs_type)
            || device == "none"
            || mount_point.starts_with("/sys")
            || mount_point.starts_with("/proc")
            || (fs_type == "overlay" && mount_point.starts_with("/var/lib/docker"))
        {
            continue;
        }
        out.push(MountEntry {
            device: device.to_owned(),
            mount_point: mount_point.to_owned(),
            fs_type: fs_type.to_owned(),
        });
    }
    out
}

/// Go's `saturatingBlockBytes`: blocks times block size, capped at the
/// largest `u64`.
pub fn saturating_bytes(blocks: u64, block_size: u64) -> u64 {
    if blocks == 0 || block_size == 0 {
        return 0;
    }
    blocks.saturating_mul(block_size)
}

/// Go's `StatfsMountPoint` arithmetic: used is total minus free (the root
/// reserve counts as used), available is what unprivileged users get, and
/// the percent is used over total.
pub fn usage(entry: &MountEntry, capacity: &Capacity) -> MountUsage {
    let block_size = u64::try_from(capacity.block_size).unwrap_or(0);
    let total = saturating_bytes(capacity.blocks, block_size);
    let available = saturating_bytes(capacity.available_blocks, block_size);
    let free = saturating_bytes(capacity.free_blocks, block_size);
    let used = total.saturating_sub(free);
    let use_pct = if total > 0 {
        used as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    MountUsage {
        device: entry.device.clone(),
        mount_point: entry.mount_point.clone(),
        fs_type: entry.fs_type.clone(),
        total,
        used,
        available,
        use_pct,
    }
}

/// The mount list from `proc_mounts`, with `stat` standing in for `statfs`
/// in tests.
pub fn mount_list_with(
    proc_mounts: &Path,
    stat: impl Fn(&Path) -> io::Result<Capacity>,
) -> Result<MountList, MountListError> {
    // Go reads bytes; a mount point that is not UTF-8 is listed by Go but
    // fails `statfs` here after the lossy conversion (not seen in practice).
    let bytes = std::fs::read(proc_mounts).map_err(MountListError::NoDfFallback)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut list = MountList::default();
    for entry in parse_mounts(&text) {
        match stat(Path::new(&entry.mount_point)) {
            Ok(capacity) => list.mounts.push(usage(&entry, &capacity)),
            Err(error) => list.skipped.push((entry.mount_point, error)),
        }
    }
    Ok(list)
}

/// The mount list of this host.
pub fn mount_list() -> Result<MountList, MountListError> {
    mount_list_with(Path::new("/proc/mounts"), disk::statfs)
}
