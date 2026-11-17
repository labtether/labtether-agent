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
  it has no token, and saves the agent token (mode 0600); a token that found
  no Hub at start is used as soon as the Hub answers, before any wait for
  approval; the CA the Hub returns is saved as `ca.crt` and trusted from the
  next connection, at start or later (not with CA-only on or over a CA file
  you set);
- keeps one WebSocket open, pings every 25 s, reconnects with a growing wait
  (1 s to 60 s), and re-enrolls with a staged token after three refused
  connects, also when its first enrollment failed (the token is kept until
  the Hub accepts it; a refused one is tried at most every 10 minutes);
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
- answers two more pages on Linux, each program through the command rules:
  - `users.list`: runs `who` and reads its lines as Go does, login times in
    the host's zone (`TZ`, else `/etc/localtime`, read with Go's rules)
    sent as UTC, a yearless C-locale time dated as Go dates it;
  - `cron.list`: runs `systemctl list-timers --all --no-pager --plain`
    (none when `systemctl` is missing), then reads the user crontabs in
    `/var/spool/cron/crontabs` and `/var/spool/cron`, `/etc/cron.d` and
    `/etc/crontab` with Go's skip rules and Go's error text;
- answers the Logs page on Linux, `journalctl` through the command rules:
  - `journal.query`: `journalctl --no-pager --output=json --lines=N
    --reverse` plus `--since`, `--until`, `--unit`, `--priority` and
    `--grep` when set (Go passes the short forms `-n -r -u -p`), 200 entries
    by default and at most 1000, 20 s, 8 MiB of output, lines of up to
    256 KiB, and Go's error texts;
  - the live stream: `journalctl --follow --output=json --lines=0` runs for
    the life of the agent and new entries go to the Hub as `log.batch`
    messages the Hub did not ask for: at most 50 per batch, a batch sent
    when full or when an entry arrives more than 2 s after the last send,
    entries dropped while no connection is open, a line of 256 KiB or
    more skipped, and a failed `journalctl` started again after 1 s,
    doubling to 32 s, as Go's `LogManager`.
    `LABTETHER_LOG_STREAM_ENABLED=false` turns it off;
- sends a Linux host's Docker inventory without being asked, as Go's
  Docker collector does (`crates/capabilities/src/docker/`), reading the
  engine over its Unix socket (`LABTETHER_DOCKER_SOCKET` or
  `docker_endpoint` in `agent-config.json`, else `/var/run/docker.sock`;
  `DOCKER_HOST` is not read, as in Go) with hyper's HTTP/1 client, at
  unversioned paths, 5 s to connect, 30 s a request, 10 MiB a reply:
  - `docker.discovery` (the whole inventory) at start, on the first round
    of each new connection, every full-reconcile period (ten discovery
    intervals, 5 to 30 min), and after a network, volume or image event
    when the inventory changed; `docker.discovery.delta` (containers and
    Compose stacks only) when containers changed, checked every discovery
    interval (30 s) and soon after a container event (350 ms after a
    start, stop, die, destroy, create or rename, else 1.2 s; each new event
    restarts the wait), and a full inventory instead when 200 or more, or
    most, containers changed; at most 500 containers, Compose stacks from
    their labels, and a stopped project kept from `compose-projects.json`
    in the state folder while its files exist;
  - `docker.stats` for the running containers, each sampled on its own
    interval (halved while busy, grown while quiet, doubled after a failed
    read), at most 24 per tick, every half discovery interval (5 to 20 s);
  - `docker.events` as the engine sends them, the stream reopened after
    1 s, doubling to 30 s;
  - the endpoint in each heartbeat's `connectors`, which the Hub reads to
    set up its Docker collector for the host.
  `LABTETHER_DOCKER_ENABLED=false` turns it off, `true` lists the endpoint
  even when it does not answer; the collector starts only when the
  endpoint answered at start. The discovery leaves out Go's Compose action
  version, as this agent answers no Docker request;
- sends a Linux host's web services without being asked, as Go's web
  service collector does (`crates/capabilities/src/webservices/`):
  `webservice.report` an interval after start and then every
  `LABTETHER_SERVICES_DISCOVERY_INTERVAL` (60 s, 10 min in low-power mode,
  30 s to 6 h). Each running container's published TCP web ports become
  services (one for a known service, at most four for another), named,
  sorted and given a health path by the registry of 172 known services
  (`webservices/registry/`, one file per category, Go's catalog without the
  descriptions) by image, then container name, then image name, and by the
  container's `labtether.name`, `labtether.category`, `labtether.icon` and
  `labtether.hidden` labels. The containers come from the Docker page's
  engine when its collector runs (`LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED`
  or `services_discovery_docker_enabled` turns this source off); the last
  report's Docker services are kept while the container list fails, until
  the next connection. Each service is checked as Go checks it: HEAD, then
  GET, at its health path; the other scheme after no answer or a 400, the
  better answer winning and its scheme becoming the URL; 2 s a request,
  no redirect followed, any certificate first and then the system roots;
  `up` under 500; a result kept three intervals when up and one when down;
  16 checks at once. A service the registry does not know is named by Go's
  recognition probes: LabTether's own `/healthz`, `/version`, `/api/health`
  and login page (one redirect on the same host followed), the root page's
  product names (and `/ui/` after a redirect), then the TrueNAS, Synology
  and QNAP APIs; every service then goes through Go's connector probes
  (Portainer, Home Assistant, TrueNAS, Proxmox Backup Server, Proxmox VE,
  Docker API, in an order set by the port), whose match of at least 0.60
  goes into `compat_*` metadata for the Hub's connector suggestions. The
  probes run one after another before the health checks, read the first
  64 KiB of a page (gzip decoded) within the same 2 s, try the other scheme
  only when nothing answered, and keep a name 15 minutes (none 5) and a
  connector match 10 minutes (none 3). LabTether's console and API are
  named, and the API is hidden when the console is listed. Services
  outside Docker come from Go's local port scan (`webservices/scan.rs`):
  Go's 49 default ports (or the list in
  `LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_PORTS`) and the lowest 128
  listening TCP ports from `/proc/net/tcp` and `tcp6`
  (`_PORT_SCAN_INCLUDE_LISTENING`), less the ports the containers' services
  already use, are dialled on the host's own address only (250 ms, 16 at
  once, a TLS hello on the usual HTTPS ports) and kept when a GET answers
  at either scheme; a port the registry gives to one service is named
  after it, at most 8 others are listed as "Port N", and the probes above
  then name and check them. `_PORT_SCAN_ENABLED` turns it off; low-power
  mode turns the scan and its listening ports off; Go's older
  `LABTETHER_WEBSVC_PORTSCAN_*` names and the `services_discovery_port_scan_*`
  keys in `agent-config.json` are read as Go reads them. Reverse proxies
  among the containers give their routes (`webservices/proxy/`,
  `routes.rs`): Traefik (its API on published port 8080, else at the host
  of an `api@internal` router in its labels; `LABTETHER_TRAEFIK_URL`,
  `_USER`, `_PASSWORD`), Caddy (its admin API on published port 2019;
  `LABTETHER_CADDY_URL`) and Nginx Proxy Manager (port 81, https unless
  `LABTETHER_ALLOW_INSECURE_TRANSPORT` is `true`, `1` or `yes`;
  `LABTETHER_NPM_URL`; it logs in with `LABTETHER_NPM_EMAIL` and
  `_PASSWORD` and keeps the token an hour), read at once with 5 s each and
  Go's client's redirects. NPM's requests pass Go's outbound rules
  (`LABTETHER_OUTBOUND_*`), so a local NPM needs
  `LABTETHER_OUTBOUND_ALLOW_LOOPBACK`. A route goes to the service of the
  container its Traefik router labels name, else of the first container
  publishing the backend's port, else of the one service on that port:
  its URL becomes the proxied one (the old one kept as `raw_url`, more
  domains in `alt_urls`); other routes become services of their own
  (source `proxy`, named by the registry from the backend's port or the
  domain). The last report's proxy services are kept while a provider
  fails. `LABTETHER_SERVICES_DISCOVERY_PROXY_ENABLED` (or Go's older
  `LABTETHER_PROXY_DISABLED`) and `_PROXY_TRAEFIK_ENABLED`,
  `_CADDY_ENABLED`, `_NPM_ENABLED` turn them off. No probe goes to a URL
  Go cannot parse (a proxy backend such as `{upstream}:3000`). The report
  says the LAN scan source is not enabled.
  `webservice.sync` (the Services page's sync) runs one cycle at once, after
  any cycle in progress, and advertises `cap_web_services=sync`;
- checks the agent token's capability claims before any handler runs, with
  the Go agent's table (`command_authorization.go`); the Hub's opaque tokens
  carry no claims and are not checked, as in Go;
- runs page requests on at most 20 worker threads, as Go runs at most 20
  handlers; one more request closes the connection, as in Go;
- serves the Go agent's local API on `AGENT_PORT` (see "Local API" below)
  and keeps the alerts the Hub pushes (`alert.notify`) for its status page;
- stops when the process in `LABTETHER_PARENT_PID` is gone, as the Go agent
  does for the macOS and Windows apps that start it.

The heartbeat says `agent_capability_mode=explicit`, so the Hub sends this
agent only the requests it advertises and answers every other one itself
with 422 `agent_unsupported` (the Hub's `internal/agentcaps`). Each `cap_*`
word comes with the handler that answers it: registering a handler adds the
Hub's word for that request (`crates/core/src/offers.rs`), and no page can
set a `cap_*` key itself. On Linux that is `cap_disks=list`,
`cap_network=list`, `cap_processes=list`, `cap_users=list`,
`cap_schedules=list` and `cap_web_services=sync`; with `systemctl` in the
agent's `PATH`
`cap_services=list`; with a package tool `cap_packages=list`; with
`journalctl` `cap_logs=stored,query,stream`, without it `cap_logs=stored`.
A page whose program is missing is not registered and sends no `cap_*` key
(Go sends an empty value and answers with an error). Go sends `list,action`
for services and packages; this agent has no actions, so it sends `list`.
The host keys are Go's: `network_backend=ifconfig` and
`network_action_backend=none` (a Linux host without `netplan` or `nmcli`),
`service_backend` (`systemd` or `none`), `package_backend` (the tool Go would
name: `apt-get`, `dnf`, `yum`, `zypper`, `pacman`, `apk`, else `dpkg-query`
or `rpm`, or `none`) and `log_backend` (`journalctl` or `none`). Both agents
decide these once at start. The `capabilities` list stays empty, so the Hub
offers no terminal, desktop, files or power. Linux sends no `agent_edition`:
the Hub reports an edition only for `monitoring`, and the console shows none
without it. Heartbeat details the Go agent learns by running a program
(`tailscale status`) are not sent.

## macOS: the monitoring edition

The Mac App Store edition of the Mac app will bundle this agent. A Store app
runs in the App Sandbox, so on macOS the agent reports and starts no
program:

- telemetry with the Go agent's macOS formulas (gopsutil v4.26.9): CPU from
  the Mach `HOST_CPU_LOAD_INFO` ticks, memory as pages in use over all pages
  with inactive pages counted free (`HOST_VM_INFO`, `hw.memsize`), disk as
  `statfs("/")` used over used plus available, and network bytes summed over
  every interface, loopback included;
- the heartbeat's host details from `sysctl` (`kern.osproductversion`,
  `kern.osrelease`, `hw.machine`, `machdep.cpu.brand_string`,
  `hw.physicalcpu`, `hw.logicalcpu`, `hw.memsize`) and `gethostuuid` for
  `host_id`, with `os_name` `macOS` as the Go agent names it;
- `disk.list`: the mount table (`getfsstat`) with `df -kP`'s arithmetic,
  used space per APFS volume (`getattrlist`), and Go's rules for which
  mounts to leave out;
- `network.list`: the interface table (`sysctl NET_RT_IFLIST2`), parsed
  as Go's `net.Interfaces` parses it, with `netstat`'s link counters.

Byte and packet counters come from `net.link.generic.ifalldata` (`struct
ifmibdata`, `<net/if_mib.h>`), which gives whole 64-bit values, also in the
sandbox and without an entitlement. The interface table and `getifaddrs`
cannot be used for them: macOS gives a program that is not part of the
system only the low 32 bits of each byte counter there, rounded down to
1 KiB, so they would wrap every 4 GiB. If `ifalldata` cannot be read, the
agent logs a warning once and falls back to those cut counters.

Not on macOS: the process list (the sandbox refuses `/bin/ps`), temperature
(Apple silicon has it only behind a private interface), the Apple silicon
clock speed, Tailscale details beyond `tailscale_installed`, and a real MAC
address when macOS 27 gives the placeholder `02:00:00:00:00:00` (the Go
agent asks `networksetup`; this agent sends no MAC then). The heartbeat
carries `disk_root_available_bytes`, which the Go agent sends on Linux only.
`crates/security` is empty on macOS, so nothing in the macOS build can start
a process. The heartbeat says `agent_capability_mode=explicit`,
`agent_edition=monitoring` (the console shows "Monitoring only"),
`cap_disks=list` and `cap_network=list`.

The system calls live in `crates/macos-sys`, the only crate allowed
`unsafe`: each block holds one call and a `SAFETY` comment, and the crate
returns plain values or raw bytes. The parsing (interface table, mount
arithmetic, host details) is safe code in `crates/platform/src/macos/`.

## Command rules

`crates/security` holds the Go agent's rules for every command the agent
starts (`internal/securityruntime`). The binary builds one `CommandPolicy`
at start from the settings and the environment it read, and hands it to
`capabilities::all` inside a `Commands` value; the service, package,
users, scheduled jobs and logs pages start every program through it, on
their worker threads; the log stream's `journalctl --follow` starts with
`CommandPolicy::start_streaming`, the same checks with the output read while
it runs, and ends with the agent.

- Exec allowlist: Go's default program list, `LABTETHER_EXEC_ALLOWLIST_MODE`
  with `LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK`, `LABTETHER_EXEC_ALLOWED_BINARIES`
  and `LABTETHER_EXEC_BLOCKED_BINARIES`. A program given with a folder must
  be the file the agent's `PATH` finds for its name (links resolved), and
  that file is what starts; a relative path with a folder is refused.
- Shell commands: Go's parser (no shell, operators refused), the prefix rules
  (`LABTETHER_SHELL_COMMAND_ALLOWLIST_*`), blocked substrings and words.
- Read-only readers: `journalctl` may not rotate or vacuum, in full or with
  any shortened form of those options; `cat`, `head`,
  `tail` and `grep` may not read the agent's own files or system secrets, and
  `grep` may not recurse.
- Child environment: only Go's list of variables, taken from the environment
  read at start.
- `CommandPolicy::run` is the only way to start a process. It checks the
  program, gives it no stdin and its own process group, keeps output up to a
  limit (8 MiB by default), and on timeout sends SIGKILL to the whole group.
  It waits at most 1 s for the output pipes after the command ends, then
  closes them; no thread outlives the call. Go's plain helpers
  (`CaptureCombinedOutput`, `CaptureOutput`) do the same on Linux and macOS
  since the command-rule fixes of 2026-11-16, so both agents give the same
  result when a timeout hits a command whose descendants hold its output.
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
(on macOS; on Linux only NPM's requests read it),
`LABTETHER_DOCKER_*`, `LABTETHER_FILES_ROOT_MODE`,
`LABTETHER_LOG_STREAM_ENABLED` (on macOS only; read on Linux),
`LABTETHER_WEBRTC_*`,
`LABTETHER_CAPTURE_FPS` and the `LABTETHER_SERVICES_DISCOVERY_*` switches
other than the Docker source, the proxies, the local port scan and the
interval.
The agent lists the ones that are set in one debug line at start.

## Not yet

This binary is not hardened and not a replacement for the Go agent:

- outbound rules for NPM's requests only: the enrollment request and the
  WebSocket dial do not refuse loopback or private addresses the way the
  Go agent's outbound policy does;
- no Tailscale details beyond whether it is installed, no connector probes
  for Proxmox, PBS, TrueNAS or Home Assistant ports (the Docker endpoint is
  the only connector), and no `cap_*` words for pages it does not answer;
- no `df -kP` fallback: when `/proc/mounts` cannot be read, `disk.list`
  replies with an error saying so (Go runs `df` then);
- no actions: `process.kill`, `network.action`, `service.action`,
  `package.action` and every other request without a handler is not
  advertised, so the Hub does not send it; one that arrives anyway is
  ignored and logged once at debug level;
- no HTTP heartbeat while the WebSocket is down;
- no start without a Hub address: Go runs on and its status page says
  `disconnected`; this agent exits (the apps never start it without one);
- no Windows parent watch (Go waits on a process handle there);
- no Docker request that changes anything: container and Compose actions,
  exec, container logs and the endpoint test are not advertised
  (`cap_docker=manage`), so the Hub refuses them; Docker is read only over
  a Unix socket (Go also reads an http(s) endpoint);
- web services from containers, reverse proxies and the local port scan
  only: no LAN scan. The probes and the proxy API requests read no
  `HTTP_PROXY` variable, speak HTTP/1.1 only and open a connection per
  request;
- no terminal, files or Remote View pages;
- a stream line of 256 KiB or more: this agent skips it and goes on, as
  the Go agent does from its fix for that line; a Go agent without the fix
  stops streaming there until it restarts;
- Go starts `systemctl list-timers` without its command rules; this agent
  starts it through them, so a blocked `systemctl` is refused and the child
  gets the cleaned environment;
- no self-update, installer, systemd unit or container image;
- Linux and macOS only; macOS has the monitoring set above.

## Layout

| Folder | Holds |
|---|---|
| `crates/config` | The settings, read from the environment and `agent-config.json` |
| `crates/platform` | Linux readers (`linux/`): `/proc`, `/sys`, `statfs`, the interface list from netlink, the mount and process lists, the PATH lookup, process-group stop, the parsers of `systemctl` and package-tool output (`linux/tool_output/`), `who` and `systemctl list-timers` text, crontab files, and Go's `time.Local` and time parsing (`gotime/`). macOS readers (`macos/`): telemetry, host details, the interface table and mount list, on top of `crates/macos-sys` |
| `crates/macos-sys` | macOS only: the system calls behind safe functions (`sysctl`, the interface table and its counters, Mach host statistics, `getfsstat`, `getattrlist`, `gethostuuid`); the one crate with `unsafe` |
| `crates/security` | The command rules, `CommandPolicy::run` and `CommandPolicy::start_streaming`, the only ways to start a process |
| `crates/core` | Device key, TLS, enrollment, connection, reconnect, token check, dispatch, request workers, producers (features that send on their own), heartbeat, telemetry loop, offline buffer, `config.update` |
| `crates/capabilities` | One module per device page: its request handlers and what the heartbeat advertises; `Commands`, the command rules handed to pages that run a program |
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
   decode, as Go does. Registering the handler advertises the Hub's word
   for the request; `features.advertise` is for host keys such as
   `service_backend` only. Register a handler only where the page answers
   (not when its program is missing).
3. Add the module and one line to `PAGES` in `crates/capabilities/src/lib.rs`.
   A page that starts a program takes a third argument, `&Commands`, starts
   every program with `commands.policy.run`, and goes in `COMMAND_PAGES`
   (Linux only). Go replies to some requests it cannot use (`package.list`
   does); such a page uses `features.on_message`, which gets the whole
   message, instead of `on_request`. A page that sends messages the Hub did
   not ask for (the log stream) adds a producer with
   `features.on_start(name, produce)`: it runs on its own thread for the
   life of the agent, outside the request workers, and sends through the
   `HubSender` it is given. A send waits until its frame is written and
   fails when no connection is open or the connection ends first, as Go's
   `Send`; the message is then dropped, never sent on a later connection.
   It waits at most the write timeout plus 1 s, whatever the connection's
   writer does.
   The `Stop` it is given is set when the agent stops; `stop.on_stop` ends a
   program the producer started.
4. If the request has no row in `crates/core/src/offers.rs`, registering it
   panics: copy the Hub's word from `messageNeeds` in the Hub's
   `internal/agentcaps/agentcaps.go` to that table and to the table in
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
interface table built byte by byte, made-up mount rows and tick counts.
The `who`, `systemctl list-timers` and crontab readers are compared with
the Go agent's own answers for the same fixtures, recorded in
`crates/platform/testdata/go/` in three time zones. The Users and
Scheduled jobs handlers run stand-in programs through the command rules
(`crates/capabilities/tests/command_pages.rs`). The journal line reader and
the logs query are compared with the Go agent's own answers for the same
fixtures and stand-in `journalctl` programs
(`crates/platform/testdata/go/journal-lines.json`,
`crates/capabilities/src/tests/testdata/go/`). The Docker page replays
Docker Engine answers recorded on a lab host and compares every message,
step by step, with what the Go collector sent for the same answers
(`crates/capabilities/src/docker/tests/testdata/`). The web service page
runs recorded container lists and tables of probe answers (pages and APIs
like each product the Go probes know) through each cycle and compares
every report and every probe request, the recognition probes in order,
with what the Go collector did for the same inputs; its registry, the
login page's redirect target and the cache pruning are compared with Go's
too (`crates/capabilities/src/webservices/tests/testdata/`); its probe
client is tested against stand-in services on loopback. The local port
scan runs through the same cycles against a stand-in for the host whose
listening ports and connections match what Go's scan met in an empty
network namespace with the scenario's listeners on loopback; the
`/proc/net/tcp` reader and the port list setting are compared with Go's
over made-up and captured text. The producer path is tested
against a Hub that stops reading, drops the connection or is offline
(`crates/core/tests/producers.rs`). CI
runs the checks on Linux and on macOS. A test fails when a page is
advertised without its handler, or handled without its advertisement. Behaviour on a real Hub is checked on
the lab machines, not in CI.
