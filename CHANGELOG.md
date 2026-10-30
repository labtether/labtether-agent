# Changelog

All notable changes to `labtether-agent` are documented in this file.

## [1.7.0] - unreleased

Changes since v1.5.1, the last public binary release.

### Security

- Linux VNC desktop sessions now refuse to start without a password, and the
  password is passed to x11vnc through a private file that is deleted after
  use, never on the command line.
- On Windows, the agent token, enrollment state and device key are private to
  the agent, SYSTEM and Administrators from the moment the file is created.
- Self-update sends the Hub token only to the Hub's own release endpoint,
  never to a custom mirror or a redirected download host.
- TLS certificate and hostname checks stay on through enrollment, reconnect
  and Hub address changes, including trusted IPv6 redirect hosts.
- Timed-out or canceled remote commands and package updates now stop their
  whole process group on Linux, so child processes do not keep running.
- Command output, log reads and session input are bounded, so a misbehaving
  process or peer cannot exhaust agent memory or hang a handler.
- Dependency, CodeQL and runtime trust-boundary fixes.

### Added

- Single-monitor VNC capture on multi-monitor X11 desktops.
- X11 WebRTC keyboard control that follows the active keymap (needs
  `xdotool` and `xmodmap`).
- Docker over a Windows named pipe, and Docker container log streaming.
- Docker Compose actions (protocol v2) run against the exact project the Hub
  showed: its working directory and ordered config files from the Compose
  labels, on the collector's own Docker endpoint, including HTTPS endpoints
  with verified TLS. See `docs/DOCKER_COMPOSE.md`.
- The container image keeps its state in `/var/lib/labtether` (mount a volume
  there) and accepts a read-only enrollment token file. A consumed token that
  cannot be deleted is remembered and never used again.

### Changed

- Licensed under the Apache License 2.0.
- Release binaries are built and signed locally with the Ed25519 release key
  (`.sig` and `.metadata.json` assets) instead of in GitHub Actions; the README
  shows how to verify them. The container image keeps its GitHub attestation.
- Needs a Hub that speaks protocol v1.7.0. Built with Go 1.27.3.
- Releases ship Linux and Windows binaries for amd64 and arm64. macOS uses the
  native app; FreeBSD is not shipped.

### Fixed

- A stale or slow session start can no longer close or replace a newer
  terminal, desktop, Docker exec, WebRTC or audio session; input arrives in
  order.
- Terminal and desktop streams stop when the Hub connection fails.
- Fixes for clipboard on macOS, Linux and Windows, Docker stats, macOS logs and
  package inventory, disk metadata, BusyBox process lists, Netplan rollback and
  network connectivity probes.
- Restarted agents keep the Hub addresses, group and CA trust saved at
  enrollment.
- Windows `full` files mode covers every fixed local drive, not only the
  system drive. Copies work between drives; a move between drives is refused.
- The first heartbeat waits for the first real reading, so Windows and macOS
  hosts no longer report all-zero CPU, memory and disk at start.
- Desktop diagnose answers within the Hub's 15 s wait. The X display scan
  looked up the desktop session and logins once per display, up to 100 times.
- Hub settings that need a restart no longer show as in use before it. The
  files root mode now applies at once. For Docker, service discovery and
  WebRTC start-up settings, the agent reports its running value and restarts
  itself under systemd or as a Windows service.
- Self-update downloads no longer fail on slow links. A download stops only
  when no data arrives for 60 seconds, or after 30 minutes in total.
- Command results send the command's real exit code (protocol `exit_code`),
  so a command that exits 2 reports 2, and 0 is sent for a clean exit. The
  output holds only what the command printed, without text such as
  `exit status 2`. No exit code is sent after a timeout, a cancel, a signal
  or a failed start.
- Windows devices run the read-only commands the Hub allows by default:
  `whoami`, `hostname`, `ipconfig`, `ipconfig /all`, `systeminfo`,
  `tasklist`, `cmd /c ver` and `powershell -Command Get-Date`. An allowlist
  rule starting with `=` must match the whole command, and rules for `cmd`,
  `powershell` and other interpreters always must, so `ipconfig /release`
  and `hostname newname` stay refused.

## Before 1.7.0

These changes shipped in v1.5.1 or earlier. In 1.7.0, release signing moved
from GitHub Actions to the maintainers' local release process.

### Security

- **Self-update requires a signed release.** `verifyReleaseMetadataSignature`
  now fails closed when `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` is not
  set. Operators who knowingly want to accept unsigned releases must also
  set `LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED=true`; a warning is logged on
  every apply in that mode.
- **SSH key install/remove rejects multi-entry payloads.** Hub-supplied
  public keys are parsed with `golang.org/x/crypto/ssh.ParseAuthorizedKey`
  and must be a single, well-formed authorized-keys line. Embedded newlines
  or trailing content is rejected. Closes a persistence primitive where a
  compromised hub could smuggle extra authorized-keys entries that the hub
  UI could not revoke via the normal "remove" flow.
- **Exec and shell allowlist off-switches now require a matching
  `_ACCEPT_RISK=true` flag.** Setting `LABTETHER_EXEC_ALLOWLIST_MODE=false`
  or `LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE=false` on its own is no
  longer sufficient — the agent refuses exec/shell requests until the
  corresponding `LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK=true` /
  `LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK=true` is also set.
- **Startup security banner.** The agent logs a prominent warning at
  startup if it boots with any security control disabled or in an
  inconsistent (mode-off, accept-risk-unset) state.

### Added

- `scripts/release/sign-release.go` — CI helper that signs the canonical
  release metadata (`version\nos\narch\nsha256\nsize`) with an
  ed25519 seed/private key read from stdin. Emits a `.sig` file and a
  `.metadata.json` file suitable for upload as release assets.
- `.github/workflows/release.yml` gained a "Sign release metadata" step
  that activates when the `RELEASE_SIGNING_PRIVATE_KEY` repo secret is
  present. Absent the secret, the step is a no-op and releases continue
  to ship unsigned (equivalent to pre-change behavior).

### Breaking

If you currently run the agent with either of the following, you must add
the companion flag before upgrading, or the agent will refuse to auto-
update / refuse to run commands:

- `AutoUpdateEnabled=true` (from hub runtime settings) without
  `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` set → also set
  `LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED=true` as a temporary escape
  hatch, or configure a trusted public key and tag a signed release.
- `LABTETHER_EXEC_ALLOWLIST_MODE=false` → also set
  `LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK=true`.
- `LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE=false` → also set
  `LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK=true`.
