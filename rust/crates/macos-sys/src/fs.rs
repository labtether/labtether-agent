//! The mount table (`getfsstat`), a volume's own used space
//! (`getattrlist(ATTR_VOL_SPACEUSED)`) and the host UUID (`gethostuuid`):
//! what `df -kP` and gopsutil's host ID read.

use std::ffi::{CString, c_char, c_int};
use std::io;
use std::mem;
use std::ptr;

/// One mounted filesystem, as `getfsstat` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStat {
    /// `f_mntfromname`: the device (`/dev/disk3s1s1`, `map auto_home`).
    pub from: String,
    /// `f_mntonname`: the mount point.
    pub on: String,
    /// `f_fstypename` (`apfs`, `devfs`, `autofs`).
    pub fs_type: String,
    pub flags: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    /// `f_bsize`, the unit of the three block counts.
    pub bsize: u32,
}

fn text(raw: &[c_char]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn fs_stat(raw: &libc::statfs) -> FsStat {
    FsStat {
        from: text(&raw.f_mntfromname),
        on: text(&raw.f_mntonname),
        fs_type: text(&raw.f_fstypename),
        flags: raw.f_flags,
        blocks: raw.f_blocks,
        bfree: raw.f_bfree,
        bavail: raw.f_bavail,
        bsize: raw.f_bsize,
    }
}

/// Every mounted filesystem, in the kernel's order, with fresh counts
/// (`MNT_WAIT`, as `df` asks for them). A mount added between the count and
/// the read is caught by asking again.
pub fn mounts() -> io::Result<Vec<FsStat>> {
    for _ in 0..4 {
        // SAFETY: a null buffer with size 0 asks only for the number of
        // mounted filesystems; nothing is written.
        let count = unsafe { libc::getfsstat(ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        let count = usize::try_from(count).map_err(|_| io::Error::last_os_error())?;
        let room = count + 4;
        // SAFETY: `statfs` holds only integers and `c_char` arrays, for
        // which all-zero bytes are a valid value.
        let blank: libc::statfs = unsafe { mem::zeroed() };
        let mut buf = vec![blank; room];
        let bytes = c_int::try_from(room * mem::size_of::<libc::statfs>())
            .map_err(|_| io::Error::other("mount table too large"))?;
        // SAFETY: `buf` holds `room` records, `bytes` bytes in all; the
        // kernel fills at most that many records and returns how many.
        let filled = unsafe { libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_WAIT) };
        let filled = usize::try_from(filled).map_err(|_| io::Error::last_os_error())?;
        if filled < room {
            return Ok(buf[..filled].iter().map(fs_stat).collect());
        }
    }
    Err(io::Error::other("mount table kept growing"))
}

/// What `getattrlist` writes for `ATTR_VOL_INFO | ATTR_VOL_SPACEUSED`: the
/// length of the returned data, then the volume's used bytes.
#[repr(C, packed(4))]
struct SpaceUsed {
    length: u32,
    used: u64,
}

/// The bytes the volume mounted at `mount_point` uses itself. On APFS this
/// is the volume's share of its container, which is what `df` shows as
/// used; `f_blocks - f_bfree` counts the whole container.
pub fn volume_space_used(mount_point: &str) -> io::Result<u64> {
    let path =
        CString::new(mount_point).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_SPACEUSED,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = SpaceUsed { length: 0, used: 0 };
    // SAFETY: `path` is NUL-terminated; `request` is a valid `attrlist`;
    // `reply` has `size_of::<SpaceUsed>()` writable bytes and the kernel
    // writes at most that many. All three live across the call.
    let rc = unsafe {
        libc::getattrlist(
            path.as_ptr(),
            (&raw mut request).cast(),
            (&raw mut reply).cast(),
            mem::size_of::<SpaceUsed>(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let (length, used) = (reply.length, reply.used);
    if (length as usize) < mem::size_of::<SpaceUsed>() {
        return Err(io::Error::other("getattrlist returned no used space"));
    }
    Ok(used)
}

/// The hardware UUID (`gethostuuid`), the value `ioreg` shows as
/// `IOPlatformUUID`.
pub fn host_uuid() -> io::Result<[u8; 16]> {
    let mut id = [0u8; 16];
    let wait = libc::timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    // SAFETY: `id` has the 16 bytes of a `uuid_t`, `wait` is a valid
    // timespec; both live across the call.
    let rc = unsafe { libc::gethostuuid(id.as_mut_ptr(), &wait) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(id)
}
