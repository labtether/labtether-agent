//! The Services page's list: `service.list`, ported from Go's
//! `HandleServiceList` (`internal/agentcore/backends/service_handler.go`)
//! and `LinuxServiceBackend.ListServices` (`service_backend_systemd.go`).
//!
//! Two programs, as in Go, each through the command rules with Go's
//! timeout and the 8 MiB output limit: `systemctl list-unit-files` (10 s;
//! when it fails the list goes on without unit file states) and
//! `systemctl list-units` (15 s; when it fails the reply carries the error
//! and no services).
//!
//! Registered only with `systemctl` in the agent's `PATH`: then
//! `cap_services=list` and `service_backend=systemd` (Go says
//! `list,action`). Without it the list is not registered, no `cap_services`
//! is sent (Go sends `""` and still answers with an error) and
//! `service_backend=none`, so the Hub does not offer the page.
//! `service.action` is not in this agent, is not registered and is not
//! advertised.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::command_exists;
use labtether_agent_platform::tool_output::services::{
    LIST_UNIT_FILES_ARGS, LIST_UNITS_ARGS, ServiceRow, parse_unit_files, parse_units,
};
use labtether_agent_security::{CommandPolicy, RunRequest, go_outcome};
use labtether_protocol::{
    MSG_SERVICE_LIST, MSG_SERVICE_LISTED, ServiceInfo, ServiceListData, ServiceListedData,
};

use crate::Commands;

/// Go's timeouts: `list-unit-files` 10 s, `list-units`
/// (`linuxServiceListTimeout`) 15 s.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timeouts {
    pub unit_files: Duration,
    pub units: Duration,
}

pub(crate) const GO_TIMEOUTS: Timeouts = Timeouts {
    unit_files: Duration::from_secs(10),
    units: Duration::from_secs(15),
};

pub fn register(features: &mut Features, _settings: &Settings, commands: &Commands) {
    let policy = Arc::clone(&commands.policy);
    if !command_exists("systemctl", policy.search_path()) {
        features.advertise("service_backend", "none");
        return;
    }
    features.on_request(
        MSG_SERVICE_LIST,
        MSG_SERVICE_LISTED,
        request_id,
        move |request| answer(request, list_services(&policy, GO_TIMEOUTS)),
    );
    features.advertise("service_backend", "systemd");
}

fn request_id(request: &ServiceListData) -> &str {
    &request.request_id
}

fn systemctl(args: &[&str], timeout: Duration) -> RunRequest {
    let mut request = RunRequest::new("systemctl", args.iter().copied());
    request.timeout = Some(timeout);
    request
}

/// The services, or Go's error text. Blocks: run it on a worker thread.
pub(crate) fn list_services(
    policy: &CommandPolicy,
    timeouts: Timeouts,
) -> Result<Vec<ServiceRow>, String> {
    let files = systemctl(&LIST_UNIT_FILES_ARGS, timeouts.unit_files);
    let files = go_outcome(policy.run(&files), files.output_limit);
    let enabled = match files.error {
        None => parse_unit_files(&files.output),
        // Go drops the error and lists units without unit file states.
        Some(_) => HashMap::new(),
    };
    let units = systemctl(&LIST_UNITS_ARGS, timeouts.units);
    let units = go_outcome(policy.run(&units), units.output_limit);
    match units.error {
        None => Ok(parse_units(&units.output, &enabled)),
        Some(_) if units.timed_out => Err("systemctl list-units timed out".into()),
        Some(error) => Err(format!("systemctl list-units: {error}")),
    }
}

fn service_info(row: ServiceRow) -> ServiceInfo {
    ServiceInfo {
        name: row.name,
        description: row.description,
        active_state: row.active_state,
        sub_state: row.sub_state,
        enabled: row.enabled,
        load_state: row.load_state,
    }
}

/// The reply for `request`: the services, or the error and none.
pub(crate) fn answer(
    request: ServiceListData,
    list: Result<Vec<ServiceRow>, String>,
) -> ServiceListedData {
    match list {
        Ok(rows) => ServiceListedData {
            request_id: request.request_id,
            services: rows.into_iter().map(service_info).collect(),
            error: String::new(),
        },
        Err(error) => {
            log::warn!("service: failed to collect services: {error}");
            ServiceListedData {
                request_id: request.request_id,
                services: Vec::new(),
                error,
            }
        }
    }
}
