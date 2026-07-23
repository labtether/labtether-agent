<div align="center">

<img src=".github/logo.svg" alt="LabTether" width="120" />

</div>

# LabTether Agent

The cross-platform agent for [LabTether](https://labtether.com) -- reports telemetry, executes actions, and enables remote access for your machines.

[![CI](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)

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
| FreeBSD | -- | Managed agentlessly via hub connectors. No agent install required. |

Typed host power is advertised only when both native reboot and shutdown
commands are present. The fixed implementations use systemd on Linux,
`shutdown` on macOS and FreeBSD when the Go agent is deployed there, and
`shutdown.exe` on Windows. A hub `202 Accepted` response means the operating
system accepted the request; it does not claim the machine has already
completed the transition.

---

## Build From Source

Requires Go 1.26+.

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

A container image is available for environments where a containerized agent is preferred:

```bash
gh attestation verify oci://ghcr.io/labtether/labtether-agent:vX.Y.Z -R labtether/labtether-agent
docker run -d --cap-drop=ALL --security-opt=no-new-privileges \
  --mount type=bind,src=/secure/labtether-enrollment-token,dst=/run/secrets/labtether-enrollment-token,readonly \
  -e LABTETHER_WS_URL=wss://your-hub:8443/ws/agent \
  -e LABTETHER_ENROLLMENT_TOKEN_FILE=/run/secrets/labtether-enrollment-token \
  ghcr.io/labtether/labtether-agent:vX.Y.Z@sha256:RELEASE_DIGEST
```

Use the immutable digest shown by the release rather than a mutable `latest` tag.

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
