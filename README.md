<div align="center">

<img src=".github/logo.svg" alt="LabTether" width="120" />

</div>

# LabTether Agent

The cross-platform agent for [LabTether](https://labtether.com) -- reports telemetry, executes actions, and enables remote access for your machines.

[![CI](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27.2+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)

---

## Install

### Linux

Choose an exact version from [Releases](https://github.com/labtether/labtether-agent/releases), then verify it before installation:

```bash
VERSION=vX.Y.Z
ASSET=labtether-agent-linux-amd64
tmp_dir="$(mktemp -d)"
curl --proto '=https' --tlsv1.2 -fL \
  "https://github.com/labtether/labtether-agent/releases/download/${VERSION}/${ASSET}" \
  -o "${tmp_dir}/${ASSET}"
curl --proto '=https' --tlsv1.2 -fL \
  "https://github.com/labtether/labtether-agent/releases/download/${VERSION}/${ASSET}.sha256" \
  -o "${tmp_dir}/${ASSET}.sha256"
(cd "${tmp_dir}" && sha256sum --check "${ASSET}.sha256")
gh attestation verify "${tmp_dir}/${ASSET}" -R labtether/labtether-agent
sudo install -m 0755 "${tmp_dir}/${ASSET}" /usr/local/bin/labtether-agent
rm -rf "${tmp_dir}"
```

Then enroll with your hub:

```bash
umask 077
token_file="$(mktemp)"
trap 'rm -f "$token_file"' EXIT
read -r -s -p 'Enrollment token: ' enrollment_token
printf '\n'
printf '%s\n' "$enrollment_token" > "$token_file"
unset enrollment_token
sudo env \
  LABTETHER_WS_URL=wss://your-hub:8443/ws/agent \
  LABTETHER_ENROLLMENT_TOKEN_FILE="$token_file" \
  /usr/local/bin/labtether-agent
```

On later starts, the agent restores the Hub addresses saved at enrollment. To
move it to a new Hub address, set `LABTETHER_WS_URL` or
`LABTETHER_API_BASE_URL`; the other address is derived from that same origin.
If your WebSocket and API use different origins, set both variables together.
For a private Hub CA or TLS proxy, set `LABTETHER_TLS_CA_FILE` to the trusted
CA file. The agent keeps that explicit trust setting after enrollment.

For systemd service setup and full configuration, see the [agent setup guide](https://labtether.com/docs/install-upgrade/agent-install-commands-by-os).

### Windows

Pre-built Windows binaries (amd64, arm64) are also available from [Releases](https://github.com/labtether/labtether-agent/releases). Verify the published checksum and GitHub build attestation before installation. For the native Windows tray app with enrollment UI and credential management, see the [Windows Agent](https://github.com/labtether/labtether-win).

---

## What It Does

- **System telemetry** -- CPU, memory, disk, and network reported to your hub, with temperature included when the host exposes a usable sensor source.
- **Remote access** -- Terminal sessions and platform-dependent desktop sessions from the LabTether console. Desktop capture requires the platform prerequisites documented by the agent when it reports an unavailable backend.
- **Service management** -- Start, stop, and restart systemd services (Linux) or Windows services remotely.
- **Package updates** -- View and apply package updates across your fleet.
- **Docker monitoring** -- Container status, logs, and actions for Docker hosts.
- **Process management** -- List and manage running processes from the dashboard.
- **Host power controls** -- Graceful reboot and shutdown through a dedicated typed protocol, with no raw-shell fallback. The agent service must have the operating-system privileges required to change host power; an unprivileged or container-isolated agent reports failure instead of false success.

---

## Platform Support

| OS | Architectures | Notes |
|:---|:-------------|:------|
| Linux | amd64, arm64 | Primary platform. Pre-built binaries in Releases. |
| Windows | amd64, arm64 | Pre-built binaries in Releases. See also [labtether-win](https://github.com/labtether/labtether-win) for the native tray app. |
| macOS | -- | See [labtether-mac](https://github.com/labtether/labtether-mac) for the native menu bar app (bundles this agent). |
| FreeBSD | -- | Planned. Add hosts to inventory manually and use a separate SSH client today; Hub connector management and a supported agent are not available yet. |

Typed host power is advertised only when both native reboot and shutdown
commands are present. The fixed implementations use systemd on Linux,
`shutdown` on macOS and FreeBSD when the Go agent is deployed there, and
`shutdown.exe` on Windows. A hub `202 Accepted` response means the operating
system accepted the request; it does not claim the machine has already
completed the transition.

---

## Linux WebRTC input prerequisites

X11 control requires `xdotool` and `xmodmap` in addition to the desktop capture
stack. Install `x11-xserver-utils` on Debian/Ubuntu, `xorg-xmodmap` on Arch, or
`xmodmap` on Fedora, openSUSE and Alpine. Missing or failed keymap tools leave
X11 WebRTC control unavailable.

The agent reads the current X11 keymap for each new key press. Repeats, release
and disconnect cleanup use the physical key number saved for that press.
This keeps a layout change from redirecting cleanup and lets controllers share
held keys without releasing each other's holds. Keys absent from the server
keymap fail explicitly; the agent does not change the keymap or add implicit
modifier presses. A bounded internal XTEST helper sends keys without changing
the active XKB layout group. A custom `LABTETHER_EXEC_ALLOWED_BINARIES` list
must permit `labtether-x11-input` as well as `xdotool` and `xmodmap`; the default
policy already allows all three.

---

## Build From Source

Requires Go 1.27.2+.

```bash
go build -o labtether-agent ./cmd/labtether-agent/
```

Cross-compile for a different platform:

```bash
GOOS=linux GOARCH=arm64 go build -o labtether-agent-linux-arm64 ./cmd/labtether-agent/
```

For most users, download the pre-built binary from [Releases](https://github.com/labtether/labtether-agent/releases/latest) instead.

---

## Docker

The agent image is public at `ghcr.io/labtether/labtether-agent` for
`linux/amd64` and `linux/arm64`. Each release tag pushes an image with a GitHub
build provenance attestation. Verify the tag, then run it pinned to that tag's
digest (shown by `docker buildx imagetools inspect` or on the GHCR package page):

```bash
gh attestation verify oci://ghcr.io/labtether/labtether-agent:vX.Y.Z -R labtether/labtether-agent
docker volume create labtether-agent-state
docker run -d --name labtether-agent --restart unless-stopped \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --mount type=volume,src=labtether-agent-state,dst=/var/lib/labtether \
  --mount type=bind,src=/secure/labtether-enrollment-token,dst=/run/secrets/labtether-enrollment-token,readonly \
  -e LABTETHER_WS_URL=wss://your-hub:8443/ws/agent \
  -e LABTETHER_ENROLLMENT_TOKEN_FILE=/run/secrets/labtether-enrollment-token \
  ghcr.io/labtether/labtether-agent:vX.Y.Z@sha256:RELEASE_DIGEST
```

The container runs as uid 1001. It keeps the issued agent token, saved Hub
addresses and CA, settings and device key in `/var/lib/labtether`. Keep that
volume so the agent stays enrolled across container updates. A new named volume
takes its owner from the image; for a bind mount, create the host directory
with owner 1001 and mode 0700 first. The enrollment token file must be readable
by uid 1001.

The enrollment token mount can stay read-only. After enrolling, the agent tries
to delete the token file. When it cannot, it records the token as used in
`/var/lib/labtether` and ignores it on every later start, so you can remove the
secret and its mount at your next update. Do not use the mutable `latest` tag.

---

## Release signing

Release binaries published on GitHub Releases are signed with an ed25519 key.
Agents that verify self-updates against this key will refuse any update whose
signature does not match the canonical release payload
(`version\nos\narch\nsha256\nsize`).

**Public key (base64, ed25519):**

```
jM9Mqx0db6S+w6FMKDnIX2jvVp7N554+6galqPvsq88=
```

To turn on verification, set this on every agent:

```bash
export LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY="jM9Mqx0db6S+w6FMKDnIX2jvVp7N554+6galqPvsq88="
```

Maintainers: see [`docs/RELEASE_SIGNING.md`](docs/RELEASE_SIGNING.md) for
local-only signing, draft inspection, publication, and key rotation.

---

## Links

- **LabTether Hub** -- [github.com/labtether/labtether](https://github.com/labtether/labtether)
- **Documentation** -- [labtether.com/docs](https://labtether.com/docs)
- **Website** -- [labtether.com](https://labtether.com)

## License

Copyright 2026 LabTether. All rights reserved. See [LICENSE](LICENSE).
