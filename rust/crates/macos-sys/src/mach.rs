//! CPU ticks and memory page counts from the Mach `host_statistics` call,
//! the two values gopsutil reads for `cpu.Percent` and `mem.VirtualMemory`
//! on macOS (`HOST_CPU_LOAD_INFO` and `HOST_VM_INFO`).

use std::io;
use std::mem;
use std::sync::OnceLock;

/// The host port, asked for once. `mach_host_self` hands out a send right
/// each time it is called; keeping one for the life of the process avoids
/// collecting a new right on every sample.
fn host_port() -> libc::mach_port_t {
    static HOST: OnceLock<libc::mach_port_t> = OnceLock::new();
    // libc marks the declaration deprecated in favour of the `mach2` crate;
    // the call is the same.
    #[allow(deprecated)]
    *HOST.get_or_init(|| {
        // SAFETY: takes no arguments and returns the host name port of the
        // calling task; it cannot fail in a way that is unsound to observe.
        unsafe { libc::mach_host_self() }
    })
}

fn kern_result(kr: libc::kern_return_t, what: &str) -> io::Result<()> {
    if kr == libc::KERN_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "host_statistics({what}) returned {kr}"
        )))
    }
}

/// The host's CPU ticks since boot, summed over every CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTicks {
    pub user: u32,
    pub system: u32,
    pub idle: u32,
    pub nice: u32,
}

/// `host_statistics(HOST_CPU_LOAD_INFO)`.
pub fn cpu_load_ticks() -> io::Result<CpuTicks> {
    let mut info = libc::host_cpu_load_info {
        cpu_ticks: [0; libc::CPU_STATE_MAX as usize],
    };
    let mut count = libc::HOST_CPU_LOAD_INFO_COUNT;
    // SAFETY: `info` is a `host_cpu_load_info` (4 natural_t values) and
    // `count` gives its size in `integer_t` units, which the kernel reads
    // to bound what it writes; both live across the call.
    let kr = unsafe {
        libc::host_statistics(
            host_port(),
            libc::HOST_CPU_LOAD_INFO,
            (&raw mut info).cast(),
            &mut count,
        )
    };
    kern_result(kr, "HOST_CPU_LOAD_INFO")?;
    let ticks = info.cpu_ticks;
    Ok(CpuTicks {
        user: ticks[libc::CPU_STATE_USER as usize],
        system: ticks[libc::CPU_STATE_SYSTEM as usize],
        idle: ticks[libc::CPU_STATE_IDLE as usize],
        nice: ticks[libc::CPU_STATE_NICE as usize],
    })
}

/// The page counts gopsutil uses, in pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmCounts {
    pub free: u32,
    pub active: u32,
    pub inactive: u32,
    pub wire: u32,
}

/// `host_statistics(HOST_VM_INFO)`: the 32-bit `vm_statistics` gopsutil
/// reads (the page counts are 32-bit in the 64-bit flavour too).
pub fn vm_counts() -> io::Result<VmCounts> {
    // SAFETY: `vm_statistics` holds only `natural_t` integers, for which
    // all-zero bytes are a valid value.
    let mut info: libc::vm_statistics = unsafe { mem::zeroed() };
    let mut count = (mem::size_of::<libc::vm_statistics>() / mem::size_of::<libc::integer_t>())
        as libc::mach_msg_type_number_t;
    // SAFETY: `info` is a `vm_statistics` of `count` integer_t units; the
    // kernel writes at most `count` units and updates it.
    let kr = unsafe {
        libc::host_statistics(
            host_port(),
            libc::HOST_VM_INFO,
            (&raw mut info).cast(),
            &mut count,
        )
    };
    kern_result(kr, "HOST_VM_INFO")?;
    Ok(VmCounts {
        free: info.free_count,
        active: info.active_count,
        inactive: info.inactive_count,
        wire: info.wire_count,
    })
}
