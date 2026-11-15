//! Root filesystem usage, ported from Go's `readDiskUsagePercent` and
//! `readDiskCapacityBytes`. Both read `statfs("/")`; Go uses `f_bsize` as
//! the block size and `f_bavail` (blocks free to unprivileged users) as the
//! free count, so the root reserve counts as used.

use std::path::Path;

/// The `statfs` values Go reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capacity {
    pub blocks: u64,
    pub available_blocks: u64,
    /// `f_bfree`: free blocks, the root reserve included. The disk list
    /// counts used space against this one.
    pub free_blocks: u64,
    /// `f_bsize`; zero or below means unknown.
    pub block_size: i64,
}

impl Capacity {
    /// Used share of the blocks in percent, or 0 for an empty filesystem.
    pub fn used_percent(&self) -> f64 {
        if self.blocks == 0 {
            return 0.0;
        }
        let total = self.blocks as f64;
        let used = (total - self.available_blocks as f64).max(0.0);
        used / total * 100.0
    }

    /// Total and available bytes, or `(0, 0)` without a block size.
    pub fn bytes(&self) -> (u64, u64) {
        let Ok(size) = u64::try_from(self.block_size) else {
            return (0, 0);
        };
        if size == 0 {
            return (0, 0);
        }
        (
            self.blocks.wrapping_mul(size),
            self.available_blocks.wrapping_mul(size),
        )
    }
}

/// `statfs(path)`, or `None` when it fails.
pub fn capacity(path: &Path) -> Option<Capacity> {
    statfs(path).ok()
}

/// `statfs(path)` with the reason it failed.
// `f_bsize` is a C long: `i64` on 64-bit targets, `i32` on 32-bit ones.
#[allow(clippy::useless_conversion)]
pub fn statfs(path: &Path) -> std::io::Result<Capacity> {
    let stats = rustix::fs::statfs(path)?;
    Ok(Capacity {
        blocks: stats.f_blocks,
        available_blocks: stats.f_bavail,
        free_blocks: stats.f_bfree,
        block_size: i64::from(stats.f_bsize),
    })
}
