//! The two package lists, read by running the package manager's query tool
//! through the command rules: Go's `LinuxPackageBackend.ListPackages`
//! (`package_backend_linuxpm.go`) and `ListUpgradablePackages`
//! (`package_upgradable_linuxpm.go`). Both block; the page runs them on a
//! worker thread.

use std::time::{Duration, Instant};

use labtether_agent_platform::command_exists;
use labtether_agent_platform::tool_output::gotext::{lossy, trim_space};
use labtether_agent_platform::tool_output::packages::{Lister, Package, validate};
use labtether_agent_platform::tool_output::upgradable::{self, RawUpgrade, Upgrade, normalize};
use labtether_agent_security::{CommandPolicy, GoOutcome, RunRequest, go_outcome};

/// Go's `DetectLinuxPackageManager` order.
const MANAGERS: [&str; 6] = ["apt-get", "dnf", "yum", "zypper", "pacman", "apk"];

/// Go's `MaxPackageInventoryOutputBytes`: the upgradable queries keep 2 MiB.
pub(crate) const UPGRADABLE_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
/// Go's `PackageInventoryCommandTimeout`, shared by every query of one
/// upgradable list.
pub(crate) const UPGRADABLE_TIMEOUT: Duration = Duration::from_secs(45);

/// The first package manager in the agent's `PATH`, as Go detects it.
pub(crate) fn detect_manager(search_path: &str) -> Option<&'static str> {
    MANAGERS
        .into_iter()
        .find(|name| command_exists(name, search_path))
}

/// Go's `detectLinuxPackageCapability`: the backend name the heartbeat
/// carries, or `None` when the host has no supported tool.
pub(crate) fn detect_backend(search_path: &str) -> Option<&'static str> {
    detect_manager(search_path).or_else(|| {
        ["dpkg-query", "rpm"]
            .into_iter()
            .find(|name| command_exists(name, search_path))
    })
}

/// Go's choice of installed-list tool: the database of the detected
/// manager when its query tool is there, else the first query tool found.
pub(crate) fn installed_lister(search_path: &str) -> Option<Lister> {
    let found = |name: &str| command_exists(name, search_path);
    let preferred = match detect_manager(search_path) {
        Some("apt-get") if found("dpkg-query") => Some(Lister::Dpkg),
        Some("dnf" | "yum" | "zypper") if found("rpm") => Some(Lister::Rpm),
        Some("pacman") => Some(Lister::Pacman),
        Some("apk") => Some(Lister::Apk),
        _ => None,
    };
    preferred.or_else(|| {
        [Lister::Dpkg, Lister::Rpm, Lister::Pacman, Lister::Apk]
            .into_iter()
            .find(|lister| found(lister.program()))
    })
}

/// The installed packages, checked as Go checks them, or Go's error text.
/// Go runs the tool with no timeout, the 8 MiB limit and the agent's
/// sanitized environment, and returns the command's own error.
pub(crate) fn list_installed(policy: &CommandPolicy) -> Result<Vec<Package>, String> {
    let lister = installed_lister(policy.search_path())
        .ok_or_else(|| "no supported package manager".to_owned())?;
    let request = RunRequest::new(lister.program(), lister.args().iter().copied());
    let outcome = go_outcome(policy.run(&request), request.output_limit);
    if let Some(error) = outcome.error {
        return Err(error);
    }
    validate(lister.parse(&outcome.output)?)
}

/// One upgradable query: Go's `RunPackageInventoryCommand`, with what is
/// left of the shared deadline.
fn query(policy: &CommandPolicy, deadline: Instant, program: &str, args: &[&str]) -> GoOutcome {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        // Go's context has expired: the command is never started.
        return GoOutcome {
            error: Some("context deadline exceeded".into()),
            exit_code: -1,
            timed_out: true,
            ..GoOutcome::default()
        };
    }
    let mut request = RunRequest::new(program, args.iter().copied());
    request.output_limit = UPGRADABLE_OUTPUT_LIMIT;
    request.timeout = Some(left);
    // The parsers read English output: Go sets these for this child only.
    request.env_overrides = [
        ("LC_ALL", "C"),
        ("LANG", "C"),
        ("HOMEBREW_NO_AUTO_UPDATE", "1"),
        ("HOMEBREW_NO_ANALYTICS", "1"),
    ]
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .into();
    go_outcome(policy.run(&request), request.output_limit)
}

/// Go's `packageInventoryCommandError`: `None` when the query counts as
/// successful (no error, or an exit code the manager uses for "updates
/// found" or "none").
pub(crate) fn query_error(
    manager: &str,
    operation: &str,
    outcome: &GoOutcome,
    accepted: &[i32],
) -> Option<String> {
    let error = outcome.error.as_ref()?;
    if outcome.timed_out {
        return Some(format!("{manager} {operation} timed out"));
    }
    if outcome.limit_hit {
        return Some(format!(
            "{manager} {operation} output exceeded {UPGRADABLE_OUTPUT_LIMIT} bytes"
        ));
    }
    if accepted.contains(&outcome.exit_code) {
        return None;
    }
    let trimmed = trim_space(&outcome.output);
    if trimmed.is_empty() {
        return Some(format!("{manager} {operation} failed: {error}"));
    }
    let text = if trimmed.len() > 4_096 {
        format!("{}...", lossy(&trimmed[..4_096]))
    } else {
        lossy(trimmed)
    };
    Some(format!("{manager} {operation} failed: {text}"))
}

const LISTING: &str = "upgradable package listing";

/// The upgradable packages, normalized as Go does, or Go's error text.
pub(crate) fn list_upgradable(
    policy: &CommandPolicy,
    timeout: Duration,
) -> Result<Vec<Upgrade>, String> {
    let manager = detect_manager(policy.search_path())
        .ok_or_else(|| "no supported package manager found".to_owned())?;
    let deadline = Instant::now() + timeout;
    let run = |args: &[&str], accepted: &[i32]| -> Result<Vec<u8>, String> {
        let outcome = query(policy, deadline, manager, args);
        match query_error(manager, LISTING, &outcome, accepted) {
            Some(error) => Err(error),
            None => Ok(outcome.output),
        }
    };
    let rows: Vec<RawUpgrade> = match manager {
        "apt-get" => upgradable::parse_apt(&run(&["--just-print", "upgrade"], &[])?)?,
        "dnf" | "yum" => {
            let updates = run(&["check-update", "--quiet"], &[100])?;
            let format = "%{NAME}.%{ARCH}\t%{VERSION}-%{RELEASE}\n";
            let installed = query(policy, deadline, "rpm", &["-qa", "--queryformat", format]);
            if let Some(error) = query_error("rpm", "installed package lookup", &installed, &[]) {
                return Err(error);
            }
            upgradable::parse_dnf(&updates, &installed.output)?
        }
        "zypper" => upgradable::parse_zypper(&run(&["--non-interactive", "list-updates"], &[])?)?,
        // pacman exits 1 when no updates are available.
        "pacman" => upgradable::parse_pacman(&run(&["-Qu"], &[1])?)?,
        "apk" => upgradable::parse_apk(&run(&["version", "-l", "<"], &[])?)?,
        other => {
            return Err(format!(
                "upgradable package listing is not supported for {other}"
            ));
        }
    };
    normalize(rows)
}
