<div align="center">

<img src=".github/logo.svg" alt="LabTether" width="80" />

</div>

# LabTether Agent

The cross-platform agent for [LabTether](https://labtether.com) -- reports telemetry, executes actions, and enables remote access for your machines.

[![CI](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)

---

## Install

### Linux

Download the latest binary from [Releases](https://github.com/labtether/labtether-agent/releases/latest):

```bash
curl -fsSL https://github.com/labtether/labtether-agent/releases/latest/download/labtether-agent-linux-amd64 \
  -o /usr/local/bin/labtether-agent
chmod +x /usr/local/bin/labtether-agent
```

Then enroll with your hub:

```bash
labtether-agent --hub wss://your-hub:8443/ws/agent --enrollment-token YOUR_TOKEN
```

For systemd service setup and full configuration, see the [agent setup guide](https://labtether.com/docs/install-upgrade/agent-install-commands-by-os).

### Windows

Pre-built Windows binaries (amd64, arm64) are also available from [Releases](https://github.com/labtether/labtether-agent/releases/latest). For the native Windows tray app with enrollment UI and credential management, see the [Windows Agent](https://github.com/labtether/labtether-win).

---

## What It Does

- **System telemetry** -- CPU, memory, disk, network, and temperature reported to your hub.
- **Remote access** -- Terminal and desktop sessions from the LabTether console. No SSH keys or VNC clients needed.
- **Service management** -- Start, stop, and restart systemd services (Linux) or Windows services remotely.
- **Package updates** -- View and apply package updates across your fleet.
- **Docker monitoring** -- Container status, logs, and actions for Docker hosts.
- **Process management** -- List and manage running processes from the dashboard.

---

## Platform Support

| OS | Architectures | Notes |
|:---|:-------------|:------|
| Linux | amd64, arm64 | Primary platform. Pre-built binaries in Releases. |
| Windows | amd64, arm64 | Pre-built binaries in Releases. See also [labtether-win](https://github.com/labtether/labtether-win) for the native tray app. |
| macOS | -- | See [labtether-mac](https://github.com/labtether/labtether-mac) for the native menu bar app (bundles this agent). |
| FreeBSD | -- | Managed agentlessly via hub connectors. No agent install required. |

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
docker run -d ghcr.io/labtether/labtether-agent:latest \
  --hub wss://your-hub:8443/ws/agent --enrollment-token YOUR_TOKEN
```

---

## Links

- **LabTether Hub** -- [github.com/labtether/labtether](https://github.com/labtether/labtether)
- **Documentation** -- [labtether.com/docs](https://labtether.com/docs)
- **Website** -- [labtether.com](https://labtether.com)

## License

Copyright 2026 LabTether. All rights reserved. See [LICENSE](LICENSE).
