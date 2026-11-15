# LabTether agent in Rust

A Rust port of the Go agent in this repository, built in small steps. The Go
agent keeps shipping until the Rust one does the same job on real machines.
Nothing here is released yet.

## What it does so far

On Linux, the `labtether-agent-rs` binary:

- reads the same settings as the Go agent (environment first for Hub-managed
  settings, `agent-config.json` for local TLS settings) once at start;
- creates or loads the ed25519 device key in the state folder
  (`/etc/labtether` by default, the folder of `LABTETHER_TOKEN_FILE`);
- trusts the Hub with the system roots plus `LABTETHER_TLS_CA_FILE`, only the
  CA file with `LABTETHER_TLS_CA_ONLY=true`, or no checks with
  `LABTETHER_TLS_SKIP_VERIFY=true` when no CA is set;
- enrolls with a one-use token (`LABTETHER_ENROLLMENT_TOKEN` or
  `LABTETHER_ENROLLMENT_TOKEN_FILE`), or waits for approval in the Hub when
  it has no token, and saves the agent token (mode 0600);
- keeps one WebSocket open, pings every 25 s, reconnects with a growing wait
  (1 s to 60 s), and re-enrolls with a staged token after three refused
  credentials;
- samples CPU, memory, root disk, network and temperature every 10 s
  (`AGENT_COLLECT_INTERVAL`) with the Go agent's formulas, reading `/proc`,
  `/sys` and `statfs` only;
- sends a heartbeat every 20 s (`AGENT_HEARTBEAT_INTERVAL`) with the Go
  agent's hardware, OS, address and metric details, and with each heartbeat
  a telemetry sample, so the Hub shows the device online with live charts;
- keeps up to 60 samples while the Hub is unreachable and sends them, oldest
  first, after reconnecting;
- applies collect and heartbeat intervals from the Hub (`config.update`)
  within the Go agent's limits, keeps intervals set in the environment, saves
  them in `applied-config.json` and replies with the values in use.

It reports no capabilities, so the Hub offers no terminal, files or actions
for it. Heartbeat details the Go agent learns by running a program
(`tailscale status`) or that describe features (`cap_*`, desktop, WebRTC,
power, connectors) are not sent.

## Command rules

`crates/security` holds the Go agent's rules for every command the agent
starts (`internal/securityruntime`). Nothing calls it yet; the read-only
pages will be its first users.

- Exec allowlist: Go's default program list, `LABTETHER_EXEC_ALLOWLIST_MODE`
  with `LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK`, `LABTETHER_EXEC_ALLOWED_BINARIES`
  and `LABTETHER_EXEC_BLOCKED_BINARIES`. Only the program's name counts.
- Shell commands: Go's parser (no shell, operators refused), the prefix rules
  (`LABTETHER_SHELL_COMMAND_ALLOWLIST_*`), blocked substrings and words.
- Read-only readers: `journalctl` may not rotate or vacuum; `cat`, `head`,
  `tail` and `grep` may not read the agent's own files or system secrets, and
  `grep` may not recurse.
- Child environment: only Go's list of variables, taken from the environment
  read at start.
- `CommandPolicy::run` is the only way to start a process. It checks the
  program, gives it no stdin and its own process group, keeps output up to a
  limit (8 MiB by default), and on timeout sends SIGKILL to the whole group.
  It waits at most 1 s for the output pipes after the command ends (Go's
  `WaitDelay` on the remote command path), then closes them; no thread
  outlives the call.
  `rust/clippy.toml` makes `std::process::Command::new` fail clippy in every
  other place.

Settings are read once at start into `CommandSecuritySettings`; the variable
names, defaults and parsing are Go's. Error text is Go's, word for word.

The cases are JSON files in `internal/securityruntime/testdata/`; the Go and
Rust tests both read them, and `tests/go_lists.rs` reads the Go source to
check the default lists. Not here yet: the outbound network rules, file
scope, log redaction, long-running processes (terminal and desktop
sessions), and Windows and macOS.

## Not yet

This binary is not hardened and not a replacement for the Go agent:

- no outbound rules: the enrollment request and the WebSocket dial do not
  refuse loopback or private addresses the way the Go agent's outbound
  policy does;
- no Tailscale details beyond whether it is installed, no connector probes
  and no `cap_*` keys;
- no HTTP heartbeat while the WebSocket is down, and no local API with
  `/agent/telemetry` or `/metrics`;
- no terminal, files, Remote View, Docker, services, packages, logs or
  other actions (the command rules exist but nothing runs a command);
- no local API, self-update, installer, systemd unit or container image;
- Linux only.

## Layout

| Folder | Holds |
|---|---|
| `crates/config` | The settings, read from the environment and `agent-config.json` |
| `crates/platform` | Linux readers: `/proc`, `/sys`, `statfs`, the interface list from netlink, the PATH lookup, process-group stop |
| `crates/security` | The command rules and `CommandPolicy::run`, the one way to start a process |
| `crates/core` | Device key, TLS, enrollment, connection, reconnect, message handlers, heartbeat, telemetry loop, offline buffer, `config.update` |
| `agent` | The binary: reads settings, starts the connection, stops on SIGTERM |

The wire messages come from the `labtether-protocol` crate in the
[protocol](https://github.com/labtether/protocol) repository.

## Run

```bash
LABTETHER_WS_URL=wss://192.0.2.10:8443/ws/agent \
LABTETHER_TLS_CA_FILE=/etc/labtether/ca.crt \
LABTETHER_ENROLLMENT_TOKEN_FILE=/etc/labtether/enroll.token \
labtether-agent-rs
```

## Checks

Use the latest stable Rust; `rust-toolchain.toml` selects it.

```bash
rustup update stable
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The tests start a stand-in Hub inside the test process. They cover settings
precedence, the TLS rules, enrollment and its file invariants, reconnect,
keepalive, the bounded send queue, the offline telemetry buffer and
`config.update`. The Linux readers are tested against captured `/proc` and
`/sys` text and a made-up sysfs tree. Behaviour on a real Hub is checked on
the lab machines, not in CI.
