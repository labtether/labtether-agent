# Install the agent by hand

Most people should install from the hub: click **Add Device**, pick an OS and
copy the command. That command installs the agent, sets up certificate trust
and sets the release signing key for self-updates.

Use this page when you want to download, check and run the agent yourself.

## Linux

The Hub's **Add Device** install command installs the agent for you. For a
manual install, choose an exact version from
[Releases](https://github.com/labtether/labtether-agent/releases) and verify it
before installation.

Release binaries are built and signed locally by the maintainers, not by GitHub
Actions, so they have no GitHub build attestation. Each binary has a `.sha256`
checksum and an Ed25519 signature (`<asset>-<version>.sig`) over the payload
`version`, `os`, `arch`, `sha256` and `size`, one per line. The matching
`<asset>-<version>.metadata.json` holds the same fields for the self-updater.
The public key is published in this repository and in the Hub repository at
[`scripts/release/agent-release-public-key.b64`](https://github.com/labtether/labtether/blob/main/scripts/release/agent-release-public-key.b64).
This check needs OpenSSL 3:

```bash
VERSION=vX.Y.Z
OS=linux ARCH=amd64
ASSET="labtether-agent-${OS}-${ARCH}"
PUBLIC_KEY='jM9Mqx0db6S+w6FMKDnIX2jvVp7N554+6galqPvsq88='
base_url="https://github.com/labtether/labtether-agent/releases/download/${VERSION}"
tmp_dir="$(mktemp -d)"
cd "${tmp_dir}"
for file in "${ASSET}" "${ASSET}.sha256" "${ASSET}-${VERSION}.sig"; do
  curl --proto '=https' --tlsv1.2 -fL "${base_url}/${file}" -o "${file}"
done
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
  printf '%s' "${PUBLIC_KEY}" | base64 -d; } > release-key.der
printf '%s\n%s\n%s\n%s\n%s' "${VERSION}" "${OS}" "${ARCH}" \
  "$(sha256sum "${ASSET}" | cut -d' ' -f1)" "$(stat -c %s "${ASSET}")" > payload
openssl pkey -pubin -inform DER -in release-key.der -out release-key.pem
base64 -d "${ASSET}-${VERSION}.sig" > signature
sha256sum --check "${ASSET}.sha256" &&
  openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin \
    -in payload -sigfile signature &&
  sudo install -m 0755 "${ASSET}" /usr/local/bin/labtether-agent
cd - >/dev/null && rm -rf "${tmp_dir}"
```

The binary is installed only when both the checksum and the signature match;
`openssl` prints `Signature Verified Successfully` for a genuine release.

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

On later starts, the agent restores the Hub addresses saved at enrollment.
Setting `LABTETHER_WS_URL` or `LABTETHER_API_BASE_URL` overrides them; the
other address is derived from that same origin. If your WebSocket and API use
different origins, set both variables together.

The saved agent token is only sent to the Hub addresses it was issued for:
the address used to enroll and the addresses that Hub returned. To move the
agent to an address outside that list, stage an enrollment token from the Hub
at that address, as for a new install. Without one, the agent asks that Hub
for approval and never sends it the old token.

Settings chosen in the environment at install time, such as
`LABTETHER_DOCKER_ENABLED`, `LABTETHER_DOCKER_SOCKET` or
`LABTETHER_FILES_ROOT_MODE`, stay in effect: Hub settings pushes skip them.
To manage one of them from the Hub, remove it from the service environment.

For a private Hub CA or TLS proxy, set `LABTETHER_TLS_CA_FILE` to the trusted
CA file. The agent keeps that explicit trust setting after enrollment.

For systemd service setup and full configuration, see the [agent setup guide](https://labtether.com/docs/guides/managing-nodes).

## Windows

Pre-built Windows binaries (amd64, arm64) are also available from [Releases](https://github.com/labtether/labtether-agent/releases) as `labtether-agent-windows-<arch>.exe`. Check them before installation: compare `Get-FileHash -Algorithm SHA256` with the `.sha256` file, and run the signature check above on any machine with OpenSSL 3, using `OS=windows` and `ASSET=labtether-agent-windows-<arch>.exe`. For the native Windows tray app with enrollment UI and credential management, see the [Windows Agent](https://github.com/labtether/labtether-win).

Run `labtether-agent.exe install` from an elevated prompt to register the Windows service. It copies the agent to `C:\Program Files\LabTether\labtether-agent.exe`, registers the service there, and locks `C:\ProgramData\LabTether` to SYSTEM and Administrators. It stops if that folder holds files owned by another account.

## Hub SSH key

On connect, the Hub can add its SSH public key to the agent account's
`authorized_keys` (on Windows as SYSTEM, `administrators_authorized_keys`).
Before removing an agent, run `labtether-agent ssh-key remove`. It deletes the
line the agent added and any other line commented `labtether-hub` with no
options in front, such as a key the Hub has since rotated; your own keys stay.
The Windows `uninstall` command does this itself.

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

## Release signing

Release binaries published on GitHub Releases are signed locally with an
Ed25519 key. Self-update refuses any release whose signature does not match the
canonical payload (`version\nos\narch\nsha256\nsize`), and it refuses to
update at all when no trusted key is configured (unless you opt in with
`LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED=true`).

**Public key (base64, Ed25519):**

```
jM9Mqx0db6S+w6FMKDnIX2jvVp7N554+6galqPvsq88=
```

The same key is committed in this repository and in the Hub repository at
`scripts/release/agent-release-public-key.b64`. Release binaries and the
container image carry it built in, and the Hub's install command also sets it.
Agents older than this release that you installed by hand need it set:

```bash
export LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY="jM9Mqx0db6S+w6FMKDnIX2jvVp7N554+6galqPvsq88="
```

Maintainers: see [`RELEASE_SIGNING.md`](RELEASE_SIGNING.md) for
local-only signing, draft inspection, publication, and key rotation.

## Reboot and shutdown

Typed host power is advertised only when both native reboot and shutdown
commands are present. The fixed implementations use systemd on Linux,
`shutdown.exe` on Windows, and `shutdown` on macOS inside the native app. A Hub
`202 Accepted` response means the operating system accepted the request; it
does not claim the machine has already completed the transition.
