//! The mount list behind `disk.list` on macOS, ported from Go's
//! `collectMountsDF` and `withoutMacOSSystemVolumes`
//! (`internal/agentcore/system/disk.go`).
//!
//! Go runs `df -kP` and parses its text. This reads what `df` reads and
//! does its arithmetic (Apple's `file_cmds` `df.c`), so no program runs:
//!
//! - the mount table from `getfsstat(MNT_WAIT)`, in the kernel's order,
//!   every mount (Apple's `df` defines `MNT_IGNORE` as 0);
//! - used blocks from `getattrlist(ATTR_VOL_SPACEUSED)` divided by the block
//!   size (on APFS a volume's own share of its container), or
//!   `f_blocks - f_bfree` when that call fails, and 0 when `f_blocks` is not
//!   above `f_bfree`;
//! - sizes in 1024-byte blocks, converted the way `fsbtoblk` does;
//! - the percent as `used / (used + available)`, rounded up to a whole
//!   number (the UNIX 2003 mode `df` runs in), 100 when both are zero.
//!
//! Then Go's rules: leave out `devfs`, `tmpfs`, `devtmpfs` and `none`
//! devices, mount points under `/sys` or `/proc`, mounts with 0 blocks
//! (automounter maps), and the APFS volumes macOS keeps for itself. Sizes
//! are 1024-byte blocks times 1024, and the file system type is empty, as
//! `df -kP` gives none.
//!
//! Where this differs from Go's text parsing: a device or mount point with
//! several spaces in a row keeps them here; Go joins the words of `df`'s
//! line with single spaces.

use std::io;

use labtether_agent_macos_sys::{self as sys, FsStat};

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

/// The mounts. `skipped` is always empty on macOS: one call reads every
/// mount's space, so no single mount can fail on its own.
#[derive(Debug, Default)]
pub struct MountList {
    pub mounts: Vec<MountUsage>,
    pub skipped: Vec<(String, io::Error)>,
}

/// Why there is no mount list.
#[derive(Debug, thiserror::Error)]
pub enum MountListError {
    #[error("cannot read the mount table: {0}")]
    MountTable(io::Error),
}

/// `df`'s block size with `-k`.
const DF_BLOCK: u64 = 1024;

/// `df.c`'s `fsbtoblk`: `num` blocks of `fs_block` bytes as `DF_BLOCK`
/// blocks, with its integer arithmetic. A count above `i64::MAX` is
/// negative in C and gives 0.
pub fn fsbtoblk(num: u64, fs_block: u64) -> u64 {
    if i64::try_from(num).is_err() {
        return 0;
    }
    if fs_block != 0 && fs_block < DF_BLOCK {
        num / (DF_BLOCK / fs_block)
    } else {
        num.wrapping_mul(fs_block / DF_BLOCK)
    }
}

/// `df`'s Capacity column in UNIX 2003 mode: rounded up, 100 when the
/// filesystem has no blocks in use or free.
pub fn capacity_percent(used: u64, available: u64) -> f64 {
    let all = available.wrapping_add(used);
    if all == 0 {
        return 100.0;
    }
    let mut value = used as f64 / all as f64 * 100.0;
    if value - value.trunc() > 0.0 {
        value += 1.0;
    }
    value.trunc()
}

/// Go's `withoutMacOSSystemVolumes`: the APFS volumes macOS keeps for
/// itself (VM, Preboot, Update and the like) and the recovery volume.
pub fn hidden_system_volume(point: &str) -> bool {
    point == "/Volumes/Recovery"
        || (point.starts_with("/System/Volumes/") && point != "/System/Volumes/Data")
}

/// The row Go builds from `df`'s line for `fs`, or `None` when Go leaves
/// the mount out. `space_used` is the volume's own used bytes, asked for
/// only when `f_blocks > f_bfree`, as `df` does.
pub fn df_row(fs: &FsStat, space_used: impl FnOnce() -> Option<u64>) -> Option<MountUsage> {
    if fs.on.starts_with("/sys") || fs.on.starts_with("/proc") {
        return None;
    }
    if matches!(fs.from.as_str(), "none" | "tmpfs" | "devtmpfs" | "devfs") {
        return None;
    }
    let block = u64::from(fs.bsize);
    let used = if fs.blocks > fs.bfree {
        match space_used() {
            Some(bytes) if block > 0 => bytes / block,
            Some(bytes) => bytes / DF_BLOCK,
            None => fs.blocks - fs.bfree,
        }
    } else {
        0
    };
    let total_kb = fsbtoblk(fs.blocks, block);
    if total_kb == 0 {
        return None;
    }
    let used_kb = fsbtoblk(used, block);
    let available_kb = fsbtoblk(fs.bavail, block);
    Some(MountUsage {
        device: fs.from.clone(),
        mount_point: fs.on.clone(),
        fs_type: String::new(),
        total: total_kb.wrapping_mul(1024),
        used: used_kb.wrapping_mul(1024),
        available: available_kb.wrapping_mul(1024),
        use_pct: capacity_percent(used, fs.bavail),
    })
}

/// The mount list from `table`, with `space_used` standing in for
/// `getattrlist` in tests.
pub fn mount_list_from(
    table: &[FsStat],
    space_used: impl Fn(&str) -> io::Result<u64>,
) -> MountList {
    let mounts = table
        .iter()
        .filter_map(|fs| df_row(fs, || space_used(&fs.on).ok()))
        .filter(|mount| !hidden_system_volume(&mount.mount_point))
        .collect();
    MountList {
        mounts,
        skipped: Vec::new(),
    }
}

/// The mount list of this host.
pub fn mount_list() -> Result<MountList, MountListError> {
    let table = sys::mounts().map_err(MountListError::MountTable)?;
    Ok(mount_list_from(&table, sys::volume_space_used))
}
