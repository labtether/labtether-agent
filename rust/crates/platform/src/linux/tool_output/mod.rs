//! Readers of other programs' output: `systemctl` for the service list,
//! the package managers' query tools for the package lists and
//! `journalctl` for the logs page. Each takes the
//! bytes a program printed and returns rows, as the Go agent parses them;
//! the pages in `labtether-agent-capabilities` start the programs through
//! the command rules. Tests read output captured on a Debian 13 host, plus
//! output in each other package manager's documented form.

pub mod gotext;
pub mod journal;
pub mod package_names;
pub mod packages;
pub mod services;
pub mod upgradable;

#[cfg(test)]
mod tests;
