# Changelog

All notable changes to `labtether-agent` are documented in this file.

## [Unreleased]

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
