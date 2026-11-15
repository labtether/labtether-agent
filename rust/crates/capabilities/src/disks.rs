//! The Disks page: `disk.list`, ported from Go's `HandleDiskList`
//! (`internal/agentcore/system/disk.go`). Go advertises nothing for it; the
//! Hub sends it to every agent.
//!
//! Gap: when `/proc/mounts` cannot be read, Go runs `df -kP`. This agent
//! runs no outside commands yet, so it replies with an error that says so
//! (see `labtether_agent_platform::mounts`).

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::mounts::{self, MountList, MountListError, MountUsage};
use labtether_protocol::{DiskListData, DiskListedData, MSG_DISK_LIST, MSG_DISK_LISTED, MountInfo};

pub fn register(features: &mut Features, _settings: &Settings) {
    features.on_request(MSG_DISK_LIST, MSG_DISK_LISTED, request_id, |request| {
        answer(request, mounts::mount_list())
    });
}

fn request_id(request: &DiskListData) -> &str {
    &request.request_id
}

fn mount_info(mount: MountUsage) -> MountInfo {
    MountInfo {
        device: mount.device,
        mount_point: mount.mount_point,
        fs_type: mount.fs_type,
        total: mount.total,
        used: mount.used,
        available: mount.available,
        use_pct: mount.use_pct,
    }
}

/// The reply for `request`: the mounts, or the error and no mounts. Each
/// mount whose `statfs` failed is logged and left out, as in Go.
pub(crate) fn answer(
    request: DiskListData,
    list: Result<MountList, MountListError>,
) -> DiskListedData {
    match list {
        Ok(list) => {
            for (point, error) in &list.skipped {
                log::info!("disk: statfs {point}: {error}");
            }
            DiskListedData {
                request_id: request.request_id,
                mounts: list.mounts.into_iter().map(mount_info).collect(),
                error: String::new(),
            }
        }
        Err(error) => {
            log::warn!("disk: failed to collect mounts: {error}");
            DiskListedData {
                request_id: request.request_id,
                mounts: Vec::new(),
                error: error.to_string(),
            }
        }
    }
}
