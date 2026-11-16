//! The Network page's interface list: `network.list`, ported from Go's
//! `HandleNetworkList` (`internal/agentcore/sysconfig/network_handler.go`).
//!
//! Advertised as Go's Linux agent does on a host without `netplan` and
//! `nmcli` (`readCapabilityMetadataWith` in
//! `internal/agentplatform/linux/provider_metadata.go`): `cap_network` is
//! `list` (from the handler), `network_backend` is `ifconfig`,
//! `network_action_backend` is `none`. Network actions (`network.action`)
//! are not in this agent, so `action` is never advertised and the Hub
//! refuses them.

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::interfaces::{self, InterfaceRow};
use labtether_protocol::{
    MSG_NETWORK_LIST, MSG_NETWORK_LISTED, NetInterface, NetworkListData, NetworkListedData,
};

pub fn register(features: &mut Features, _settings: &Settings) {
    features.on_request(
        MSG_NETWORK_LIST,
        MSG_NETWORK_LISTED,
        request_id,
        |request| answer(request, interfaces::interface_rows()),
    );
    features.advertise("network_backend", "ifconfig");
    features.advertise("network_action_backend", "none");
}

fn request_id(request: &NetworkListData) -> &str {
    &request.request_id
}

fn net_interface(row: InterfaceRow) -> NetInterface {
    NetInterface {
        name: row.name,
        state: row.state.to_owned(),
        mac: row.mac,
        mtu: row.mtu,
        ips: row.ips,
        rx_bytes: row.rx_bytes,
        tx_bytes: row.tx_bytes,
        rx_packets: row.rx_packets,
        tx_packets: row.tx_packets,
    }
}

/// The reply for `request`: the interfaces, or the error and none.
pub(crate) fn answer(
    request: NetworkListData,
    rows: std::io::Result<Vec<InterfaceRow>>,
) -> NetworkListedData {
    match rows {
        Ok(rows) => NetworkListedData {
            request_id: request.request_id,
            interfaces: rows.into_iter().map(net_interface).collect(),
            error: String::new(),
        },
        Err(error) => {
            log::warn!("network: failed to collect interfaces: {error}");
            NetworkListedData {
                request_id: request.request_id,
                interfaces: Vec::new(),
                error: error.to_string(),
            }
        }
    }
}
