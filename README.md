<div align="center">

<img src=".github/logo.svg" alt="LabTether" width="120" />

# LabTether Agent

**Connect a Linux or Windows machine to your [LabTether](https://github.com/labtether/labtether) hub.**

[![CI](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/labtether/labtether-agent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

</div>

The hub can already see your Proxmox, TrueNAS and Docker hosts through their
APIs. Install the agent on a machine and the hub can work *on* it too: open a
terminal, view its desktop, browse its files and restart its services, all from
your browser.

## What it adds

- **Live metrics.** CPU, memory, disk and network, plus temperature when the
  machine has a readable sensor.
- **Terminal and remote desktop** from the hub. No SSH keys to copy around.
  Desktop needs a supported display setup on the machine; see
  [Linux desktop input](docs/linux-desktop.md).
- **Services.** Start, stop and restart systemd or Windows services.
- **Package updates.** See what is out of date and apply updates.
- **Docker.** Container status, logs and actions, plus Compose stacks.
- **Processes.** List and manage running processes.
- **Reboot and shutdown** through a dedicated command, never a raw shell.
- **Signed self-updates.** The agent only installs an update signed with the
  LabTether release key.

## Install

In your hub, click **Add Device**, pick your OS and copy the command. It
installs the agent, sets up certificate trust and enrolls the machine with a
one-time token.

To download and check a release yourself, or to run the agent in Docker, see
[docs/install.md](docs/install.md).

## Platforms

| OS | Builds | Status |
|---|---|---|
| Linux | amd64, arm64, container image | Supported |
| Windows | amd64, arm64 | Partial: metrics and terminal work; more is in progress |
| macOS | none on its own | Ships inside the [menu bar app](https://github.com/labtether/labtether-mac) |
| FreeBSD | none | Planned |

## Build from source

You need Go 1.27.3 or newer.

```bash
go build -o labtether-agent ./cmd/labtether-agent/
GOOS=linux GOARCH=arm64 go build -o labtether-agent-linux-arm64 ./cmd/labtether-agent/
```

## Contributing

If you work with an AI coding agent, point it at [AGENTS.md](AGENTS.md) first.
It covers the layout, the checks to run and the house rules. Release signing is
in [docs/RELEASE_SIGNING.md](docs/RELEASE_SIGNING.md), Compose actions in
[docs/DOCKER_COMPOSE.md](docs/DOCKER_COMPOSE.md), and changes in
[CHANGELOG.md](CHANGELOG.md).

## Help

- [Docs](https://labtether.com/docs) and [managing nodes](https://labtether.com/docs/guides/managing-nodes)
- [GitHub Discussions](https://github.com/labtether/labtether/discussions)
- Security issues: report privately as described in [SECURITY.md](SECURITY.md)

## License

[Apache 2.0](LICENSE). Copyright 2026 LabTether.
