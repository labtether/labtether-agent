//! Byte offsets in the [`interface_table`](crate::interface_table) and
//! [`interface_data`](crate::interface_data) dumps, taken from the C structs
//! (`<net/if.h>`, `<net/route.h>`, `<net/if_mib.h>`) with `offset_of!`, so
//! the safe parsers in `labtether-agent-platform` read the same fields the
//! kernel wrote.
//!
//! The dump is a run of messages. Each starts with `u16` length, `u8`
//! version, `u8` type. An `RTM_IFINFO2` message (`if_msghdr2`) describes
//! one interface and is followed by its link address (`sockaddr_dl`); each
//! `RTM_NEWADDR` message (`ifa_msghdr`) after it carries one address of
//! that interface as a run of socket addresses, one for each bit of its
//! address mask, each padded to 4 bytes.

use std::mem::{offset_of, size_of};

use libc::{if_data64, if_msghdr2, ifa_msghdr, ifmibdata};

/// `if_msghdr2` size: where its socket addresses start.
pub const IFM_HEADER: usize = size_of::<if_msghdr2>();
pub const IFM_ADDRS: usize = offset_of!(if_msghdr2, ifm_addrs);
pub const IFM_FLAGS: usize = offset_of!(if_msghdr2, ifm_flags);
pub const IFM_INDEX: usize = offset_of!(if_msghdr2, ifm_index);
const IFM_DATA: usize = offset_of!(if_msghdr2, ifm_data);
pub const IFI_MTU: usize = IFM_DATA + offset_of!(if_data64, ifi_mtu);
pub const IFI_IPACKETS: usize = IFM_DATA + offset_of!(if_data64, ifi_ipackets);
pub const IFI_OPACKETS: usize = IFM_DATA + offset_of!(if_data64, ifi_opackets);
pub const IFI_IBYTES: usize = IFM_DATA + offset_of!(if_data64, ifi_ibytes);
pub const IFI_OBYTES: usize = IFM_DATA + offset_of!(if_data64, ifi_obytes);

/// The [`interface_data`](crate::interface_data) dump: `ifmibdata` entries
/// of `IFMD_SIZE` bytes each, the interface name (NUL-padded) at
/// `IFMD_NAME`, then the counters of its `if_data64`.
pub const IFMD_SIZE: usize = size_of::<ifmibdata>();
pub const IFMD_NAME: usize = offset_of!(ifmibdata, ifmd_name);
pub const IFMD_NAME_LEN: usize = libc::IFNAMSIZ;
const IFMD_DATA: usize = offset_of!(ifmibdata, ifmd_data);
pub const IFMD_IPACKETS: usize = IFMD_DATA + offset_of!(if_data64, ifi_ipackets);
pub const IFMD_OPACKETS: usize = IFMD_DATA + offset_of!(if_data64, ifi_opackets);
pub const IFMD_IBYTES: usize = IFMD_DATA + offset_of!(if_data64, ifi_ibytes);
pub const IFMD_OBYTES: usize = IFMD_DATA + offset_of!(if_data64, ifi_obytes);

// The C layout, from clang's `offsetof` on the macOS 27.2 SDK
// (`if_data64` is packed to 4 bytes). A libc release that changed these
// would make other fields read as counters.
const _: () = assert!(
    IFMD_SIZE == 180
        && IFMD_IPACKETS == 76
        && IFMD_OPACKETS == 92
        && IFMD_IBYTES == 116
        && IFMD_OBYTES == 124
);

/// `ifa_msghdr` size: where its socket addresses start.
pub const IFAM_HEADER: usize = size_of::<ifa_msghdr>();
pub const IFAM_ADDRS: usize = offset_of!(ifa_msghdr, ifam_addrs);
pub const IFAM_INDEX: usize = offset_of!(ifa_msghdr, ifam_index);

pub const RTM_IFINFO2: u8 = libc::RTM_IFINFO2 as u8;
pub const RTM_NEWADDR: u8 = libc::RTM_NEWADDR as u8;

pub const AF_INET: u8 = libc::AF_INET as u8;
pub const AF_INET6: u8 = libc::AF_INET6 as u8;
pub const AF_LINK: u8 = libc::AF_LINK as u8;

pub const IFF_UP: i32 = libc::IFF_UP;
pub const IFF_LOOPBACK: i32 = libc::IFF_LOOPBACK;

/// Socket address slots, in the order they follow a header.
pub const RTAX_NETMASK: usize = libc::RTAX_NETMASK as usize;
pub const RTAX_IFP: usize = libc::RTAX_IFP as usize;
pub const RTAX_IFA: usize = libc::RTAX_IFA as usize;
pub const RTAX_BRD: usize = libc::RTAX_BRD as usize;
pub const RTAX_MAX: usize = libc::RTAX_MAX as usize;
