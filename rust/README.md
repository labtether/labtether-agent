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
  them in `applied-config.json` and replies with the values in use;
- answers three device pages with the Go agent's fields, units, order,
  limits and error replies, without running any program:
  - `disk.list`: `/proc/mounts` and `statfs` of each mount;
  - `network.list`: interfaces from netlink, counters from
    `/sys/class/net/<name>/statistics/`;
  - `process.list`: `/proc`, with the columns and rounding of the
    `ps -axo user=,pid=,%cpu=,%mem=,rss=,command=` the Go agent runs, then
    Go's sort (CPU or memory) and limit (25 by default);
- answers the service list and both package lists by running the programs
  the Go agent runs, with its arguments, timeouts, output limits and error
  replies, each through the command rules (see "Command rules"):
  - `service.list`: `systemctl list-unit-files` (10 s) for the unit file
    states and `systemctl list-units --all` (15 s) for the units, plus the
    installed services `list-units` leaves out;
  - `package.list`: the installed list from `dpkg-query`, `rpm`,
    `pacman -Q` or `apk info -v` (the database of the first package manager
    found), or with `inventory: upgradable` the available updates from
    `apt-get --just-print upgrade`, `dnf`/`yum check-update` with `rpm`,
    `zypper list-updates`, `pacman -Qu` or `apk version -l <` (45 s for
    the whole list, 2 MiB of output, `LC_ALL=C`); at most 10,000 entries
    and an 8 MiB reply, as in Go;
- checks the agent token's capability claims before any handler runs, with
  the Go agent's table (`command_authorization.go`); the Hub's opaque tokens
  carry no claims and are not checked, as in Go;
- runs page requests on at most 20 worker threads, as Go runs at most 20
  handlers; one more request closes the connection, as in Go;
- serves the Go agent's local API on `AGENT_PORT` (see "Local API" below)
  and keeps the alerts the Hub pushes (`alert.notify`) for its status page;
- stops when the process in `LABTETHER_PARENT_PID` is gone, as the Go agent
  does for the macOS and Windows apps that start it.

The heartbeat advertises `cap_network=list`, `network_backend=ifconfig` and
`network_action_backend=none`, Go's values for a Linux host without
`netplan` or `nmcli`. With `systemctl` in the agent's `PATH` it sends
`cap_services=list` and `service_backend=systemd`; with a package tool,
`cap_packages=list` and `package_backend` set to the tool Go would name
(`apt-get`, `dnf`, `yum`, `zypper`, `pacman`, `apk`, else `dpkg-query` or
`rpm`). Go sends `list,action` for both; this agent has no service or
package actions, so it sends `list`, the value Go itself uses for a host
with only a query tool. Without the tool it sends Go's empty value and
`none`. Both agents decide these once at start. The `capabilities` list
stays empty, so the Hub offers no terminal, desktop, files or power for it. Heartbeat details the Go agent
learns by running a program (`tailscale status`) are not sent.

## macOS: the monitoring edition

The Mac App Store edition of the Mac app will bundle this agent. A Store app
runs in the App Sandbox, so on macOS the agent reports and starts no
program:

- telemetry with the Go agent's macOS formulas (gopsutil v4.26.9): CPU from
  the Mach `HOST_CPU_LOAD_INFO` ticks, memory as pages in use over all pages
  with inactive pages counted free (`HOST_VM_INFO`, `hw.memsize`), disk as
  `statfs("/")` used over used plus available, and network bytes summed over
  every interface, loopback included, from the kernel's interface table;
- the heartbeat's host details from `sysctl` (`kern.osproductversion`,
  `kern.osrelease`, `hw.machine`, `machdep.cpu.brand_string`,
  `hw.physicalcpu`, `hw.logicalcpu`, `hw.memsize`) and `gethostuuid` for
  `host_id`, with `os_name` `macOS` as the Go agent names it;
- `disk.list`: the mount table (`getfsstat`) with `df -kP`'s arithmetic,
  used space per APFS volume (`getattrlist`), and Go's rules for which
  mounts to leave out;
- `network.list`: the interface table (`sysctl NET_RT_IFLIST2`), parsed
  as Go's `net.Interfaces` parses it, with `netstat`'s link counters.

Not on macOS: the process list (the sandbox refuses `/bin/ps`), temperature
(Apple silicon has it only behind a private interface), the Apple silicon
clock speed, Tailscale details beyond `tailscale_installed`, and a real MAC
address when macOS 27 gives the placeholder `02:00:00:00:00:00` (the Go
agent asks `networksetup`; this agent sends no MAC then). The heartbeat
carries `disk_root_available_bytes`, which the Go agent sends on Linux only.
`crates/security` is empty on macOS, so nothing in the macOS build can start
a process.

The system calls live in `crates/macos-sys`, the only crate allowed
`unsafe`: each block holds one call and a `SAFETY` comment, and the crate
returns plain values or raw bytes. The parsing (interface table, mount
arithmetic, host details) is safe code in `crates/platform/src/macos/`.

## Command rules

`crates/security` holds the Go agent's rules for every command the agent
starts (`internal/securityruntime`). The binary builds one `CommandPolicy`
at start from the settings and the environment it read, and hands it to
`capabilities::all` inside a `Commands` value; the service and package
pages start every program through it, on their worker threads.

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
- `RunRequest::env_overrides` sets variables for one command on top of the
  sanitized environment (the package queries' `LC_ALL=C`, as Go does).
- `go_outcome` turns a run into what Go's capture helpers return: the kept
  output and Go's error text (`exit status 1`, `signal: killed`, the output
  limit message), with the exit code and whether the timeout or the limit
  was hit.

Settings are read once at start into `CommandSecuritySettings`; the variable
names, defaults and parsing are Go's. Error text is Go's, word for word.

The cases are JSON files in `internal/securityruntime/testdata/`; the Go and
Rust tests both read them, and `tests/go_lists.rs` reads the Go source to
check the default lists. Not here yet: the outbound network rules, file
scope, log redaction, long-running processes (terminal and desktop
sessions), and Windows and macOS.

## Local API

`crates/local-api` is the Go agent's local server (`runtime.go`,
`local_status.go`, `metrics.go`, `internal/servicehttp`), on hyper's HTTP/1
server. The settings are read once at start: `AGENT_PORT` (default 8090),
`LABTETHER_AGENT_LOCAL_BIND_ADDRESS` (default 127.0.0.1),
`LABTETHER_AGENT_LOCAL_AUTH_TOKEN` or `LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE`,
and `LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED`. As in Go, a non-loopback
address without a token turns the API off unless that last variable is true,
a token file that cannot be read turns it off too, and a port that is taken
is tried again after 30 s, doubling to 5 minutes, while the agent runs on.

| Path | Token | Body |
|---|---|---|
| `/agent/status` | yes, when set | the status of the protocol repo's local agent contract, with ETag and `If-None-Match` (304) |
| `/agent/info` | yes, when set | `os`, `mode`, `status` |
| `/agent/telemetry` | yes, when set | the latest sample |
| `/metrics` | yes, when set | Prometheus text, Go's seven families |
| `/healthz`, `/readyz`, `/version` | never | Go's bodies; `/version` shows `APP_VERSION` or `dev` |

The token is compared in constant time and never logged; a refusal is Go's
401 JSON. The body bytes are Go's (field order, escapes, float and time
text), so the ETag is the one Go would give for the same state. `core`
knows no HTTP: the server reads `Agent::status_view()`.

Not in Go, so a local program cannot tie the agent up: at most 32
connections at once, request headers within 5 s and 16 KiB, no request body
read, and each connection closed after 120 s. Times are always written in
UTC; Go writes `disconnected_at` in the host's zone after a failed connect.

The status tests (`crates/local-api/tests/states.rs`) drive the real agent
into each state of the contract's fixtures against the stand-in Hub and
read the page over HTTP. The fixtures are copied from the protocol repo at
the commit in `tests/localagent/SOURCE.json`; a test fails when the copy
changes, and `scripts/localagent-contract.py check --protocol <checkout>`
compares it with the protocol repo.

Variables the apps set that this agent does not use yet. Each belongs to a
feature this agent does not have, so ignoring it changes nothing today; each
must be read when its feature arrives: `LABTETHER_AUTO_UPDATE` (no
self-update; the apps set it to `false`), `LABTETHER_OUTBOUND_ALLOW_LOOPBACK`
(no outbound rules yet, so loopback is never refused),
`LABTETHER_DOCKER_*`, `LABTETHER_FILES_ROOT_MODE`,
`LABTETHER_LOG_STREAM_ENABLED`, `LABTETHER_WEBRTC_*`,
`LABTETHER_CAPTURE_FPS` and the `LABTETHER_SERVICES_DISCOVERY_*` switches.
The agent lists the ones that are set in one debug line at start.

## Not yet

This binary is not hardened and not a replacement for the Go agent:

- no outbound rules: the enrollment request and the WebSocket dial do not
  refuse loopback or private addresses the way the Go agent's outbound
  policy does;
- no Tailscale details beyond whether it is installed, no connector probes,
  and no `cap_*` keys other than `cap_network`, `cap_services` and
  `cap_packages`;
- no `df -kP` fallback: when `/proc/mounts` cannot be read, `disk.list`
  replies with an error saying so (Go runs `df` then);
- no actions: `process.kill`, `network.action`, `service.action`,
  `package.action` and every other request without a handler is ignored
  and logged once at debug level;
- no HTTP heartbeat while the WebSocket is down;
- no start without a Hub address: Go runs on and its status page says
  `disconnected`; this agent exits (the apps never start it without one);
- no Windows parent watch (Go waits on a process handle there);
- no users, cron, logs, Docker, web service discovery, terminal, files or
  Remote View pages;
- no self-update, installer, systemd unit or container image;
- Linux and macOS only; macOS has the monitoring set above.

## Layout

| Folder | Holds |
|---|---|
| `crates/config` | The settings, read from the environment and `agent-config.json` |
| `crates/platform` | Linux readers (`linux/`): `/proc`, `/sys`, `statfs`, the interface list from netlink, the mount and process lists, the PATH lookup, process-group stop, and the parsers of `systemctl` and package-tool output (`linux/tool_output/`). macOS readers (`macos/`): telemetry, host details, the interface table and mount list, on top of `crates/macos-sys` |
| `crates/macos-sys` | macOS only: the system calls behind safe functions (`sysctl`, the interface table, Mach host statistics, `getfsstat`, `getattrlist`, `gethostuuid`); the one crate with `unsafe` |
| `crates/security` | The command rules and `CommandPolicy::run`, the one way to start a process |
| `crates/core` | Device key, TLS, enrollment, connection, reconnect, token check, dispatch, request workers, heartbeat, telemetry loop, offline buffer, `config.update` |
| `crates/capabilities` | One module per device page: its request handlers and what the heartbeat advertises |
| `crates/local-api` | The local HTTP API the apps poll, reading the agent through `Agent::status_view()` |
| `agent` | The binary: reads settings, builds the features, starts the connection and the local API, stops on SIGTERM or when the parent process is gone |

## Adding a page

1. Put the system reads in `crates/platform` as text-in, values-out
   functions, with tests on captured text. On macOS, add a page only if it
   works in the App Sandbox without starting a program, and add it to
   `crates/capabilities/tests/macos_pages.rs`.
2. Add `crates/capabilities/src/<page>.rs` with
   `pub fn register(features: &mut Features, settings: &Settings)`. Use
   `features.on_request(request_type, reply_type, request_id, answer)`:
   `answer` takes the decoded request and returns the reply payload; the
   helper sends it with the request's ID and drops a request that does not
   decode, as Go does. Advertise `cap_*` keys with `features.advertise`.
3. Add the module and one line to `PAGES` in `crates/capabilities/src/lib.rs`.
   A page that starts a program takes a third argument, `&Commands`, starts
   every program with `commands.policy.run`, and goes in `COMMAND_PAGES`
   (Linux only). Go replies to some requests it cannot use (`package.list`
   does); such a page uses `features.on_message`, which gets the whole
   message, instead of `on_request`.
4. If the page brings a new `cap_*` value, add its row to
   `crates/capabilities/tests/advertised.rs`.

The token check and the worker limit apply without further code.

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
keepalive, the bounded send queue, the offline telemetry buffer,
`config.update`, the token check, the request workers and the typed reply.
The Linux readers are tested against captured `/proc` and `/sys` text, a
made-up sysfs tree and a made-up `/proc` tree; the macOS readers against an
interface table built byte by byte, made-up mount rows and tick counts. CI
runs the checks on Linux and on macOS. A test fails when a page is
advertised without its handler, or handled without its advertisement. Behaviour on a real Hub is checked on
the lab machines, not in CI.
