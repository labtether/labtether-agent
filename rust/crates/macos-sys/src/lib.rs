//! The macOS system calls the LabTether Rust agent needs, each behind a safe
//! function. This is the only crate in the workspace with `unsafe` code;
//! everything that reads these values (`labtether-agent-platform`) keeps
//! `#![forbid(unsafe_code)]`.
//!
//! Every call here is a public, documented macOS interface that works
//! inside the App Sandbox without an entitlement: `sysctl`, the Mach
//! `host_statistics` call, `getfsstat`, `getattrlist` and `gethostuuid`. No
//! private framework is touched and no program is started.
//!
//! Rules for this crate (enforced by its lints): each `unsafe` block holds
//! one unsafe operation and says in a `SAFETY` comment why it is sound.
//! Raw bytes are returned where a parser can do the rest in safe code (the
//! interface table); fixed C structs are copied into plain Rust values.
//!
//! On other systems the crate is empty.

#![cfg(target_os = "macos")]

mod fs;
pub mod layout;
mod mach;

use std::ffi::{CString, c_int};
use std::io;
use std::ptr;

pub use fs::{FsStat, host_uuid, mounts, volume_space_used};
pub use mach::{CpuTicks, VmCounts, cpu_load_ticks, vm_counts};

/// How often a `sysctl` read is retried when the value grew between asking
/// for its size and reading it.
const SYSCTL_TRIES: usize = 8;

/// Reads a `sysctl` value of unknown size: asks for the size, then reads
/// into a buffer with some room to spare, and tries again if the value grew
/// in between (`ENOMEM`).
fn sysctl_read(
    mut call: impl FnMut(*mut libc::c_void, &mut usize) -> c_int,
) -> io::Result<Vec<u8>> {
    for _ in 0..SYSCTL_TRIES {
        let mut size = 0usize;
        if call(ptr::null_mut(), &mut size) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; size + size / 8 + 64];
        let mut len = buf.len();
        if call(buf.as_mut_ptr().cast(), &mut len) == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::other("sysctl value kept growing"))
}

/// `sysctlbyname(name)` as raw bytes.
pub fn sysctl_bytes(name: &str) -> io::Result<Vec<u8>> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    sysctl_read(|buf, len| {
        // SAFETY: `name` is NUL-terminated and outlives the call; `buf` is
        // either null (the kernel then only writes the size to `len`) or
        // points to `*len` writable bytes, and the kernel writes at most
        // `*len` bytes and stores the count in `len`. No new value is set.
        unsafe { libc::sysctlbyname(name.as_ptr(), buf, len, ptr::null_mut(), 0) }
    })
}

/// A string `sysctl` value (`kern.osrelease`), without its trailing NULs.
pub fn sysctl_string(name: &str) -> io::Result<String> {
    let bytes = sysctl_bytes(name)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// A whole-number `sysctl` value, 4 or 8 bytes wide (`hw.memsize`,
/// `hw.logicalcpu`).
pub fn sysctl_u64(name: &str) -> io::Result<u64> {
    let bytes = sysctl_bytes(name)?;
    match bytes.len() {
        4 => Ok(u64::from(u32::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        8 => Ok(u64::from_ne_bytes(bytes[..8].try_into().unwrap_or([0; 8]))),
        n => Err(io::Error::other(format!("sysctl {name}: {n} bytes"))),
    }
}

/// `sysctl(mib)` as raw bytes.
fn sysctl_mib(mut mib: [c_int; 6]) -> io::Result<Vec<u8>> {
    let mib_len = mib.len() as libc::c_uint;
    sysctl_read(|buf, len| {
        // SAFETY: `mib` holds `mib_len` integers and lives across the call;
        // `buf` is null (size only) or points to `*len` writable bytes, as
        // for `sysctlbyname` above. No new value is set.
        unsafe { libc::sysctl(mib.as_mut_ptr(), mib_len, buf, len, ptr::null_mut(), 0) }
    })
}

/// The kernel's interface table: the
/// `sysctl(CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0)` dump that
/// `netstat -i` and Go's `net.Interfaces` read. Parse it with the offsets in
/// [`layout`].
///
/// Its byte counters are cut short for this process: the kernel gives a
/// program that is not part of macOS only their low 32 bits, rounded down
/// to 1 KiB (`ALIGN_BYTES` in `sysctl_iflist2`, XNU `bsd/net/rtsock.c`), so
/// they wrap every 4 GiB. Take counters from [`interface_data`].
pub fn interface_table() -> io::Result<Vec<u8>> {
    sysctl_mib([libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0])
}

/// Every interface's statistics with whole 64-bit counters: the
/// `sysctl(CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFALLDATA, 0,
/// IFDATA_GENERAL)` dump (`net.link.generic.ifalldata`), one
/// `struct ifmibdata` (`<net/if_mib.h>`) per interface. Parse it with the
/// `IFMD_*` offsets in [`layout`].
///
/// The kernel copies these counters as they are, whoever asks
/// (`make_ifmibdata`, XNU `bsd/net/if_mib.c`), and the App Sandbox allows
/// the read without an entitlement.
pub fn interface_data() -> io::Result<Vec<u8>> {
    sysctl_mib([
        libc::CTL_NET,
        libc::PF_LINK,
        libc::NETLINK_GENERIC,
        libc::IFMIB_IFALLDATA,
        0,
        libc::IFDATA_GENERAL,
    ])
}
