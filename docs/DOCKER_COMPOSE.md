# Docker Compose endpoint selection

Compose actions use the Docker collector's configured endpoint, native project
name, working directory and ordered Compose files. The v2 action protocol also
pins the endpoint ID and selection saved by Hub. Older Hub requests keep fresh
selection at execution; they do not gain queue-time identity guarantees.

Docker discovery reports `compose_action_version: 2` and the endpoint ID only
when the collector's endpoint can be passed to the Compose CLI. Stacks whose
labels lack a project directory or ordered config files, disagree between
containers, or come from a truncated inventory carry a `selection_error`. The
agent refuses `up`, `down`, `restart` and `pull` when a fresh lookup of the
project's labels does not give one consistent selection.

## HTTPS

HTTPS requires Docker Compose **CLI v2**. Before lookup or deploy writes, the
agent makes a fresh, verified GET to the collector's `/_ping` endpoint. Redirects,
missing verified chains and hostname failures stop the action. The probe has a
five-second deadline, a 16 KiB header cap and a 4 KiB body cap.

The agent exports only the public terminal certificates from the verified
chains to an owned temporary CA file. It passes explicit `--host`,
`--tlsverify=true`, `--tlscacert`, `--tlscert=` and `--tlskey=` flags before the
`compose` subcommand. The original hostname, explicit port and base path are
preserved; omitted HTTPS ports become 443. No plaintext fallback is used.
Compose CLI v1 is refused for HTTPS. Unix sockets and HTTP keep their existing
behavior.

The CA file lives until the command has finished, including cancellation. It
and its private temporary directory are removed before the result is sent.
Cleanup errors fail the action. Only those owned paths are removed, never a
whole directory tree. POSIX permissions are 0600/0700; Windows uses the existing
user temporary-directory access controls.

The collector currently has no Docker-specific client-certificate or custom-CA
setting. HTTPS must already verify with its existing Go/system trust. This
bridge does not use Hub CA files, disable hostname verification, or add mTLS.
It does not claim physical daemon identity when a server changes at the same
URL, nor exact equivalence between Go/system verification and every CLI/OS
trust rule. Endpoint IDs pin the configured endpoint string.

Existing registry authentication remains unchanged. Explicit daemon flags and
cleared Docker context/TLS environment values prevent ambient daemon selection;
they do not replace the user's registry login configuration or helper.

## Verification scope

The focused HTTPS tests use a real TLS server and real owned child process.
They cover verified-root export, hostname/trust rejection before effects,
redirect/body limits, final TLS flags, legacy-wire compatibility and cancellation
cleanup. The child is a re-exec fixture, not Docker CLI. Actual Compose CLI and
real-daemon acceptance remain separate live checks.

The explicit empty client flags and nonempty CA file match
[Docker CLI 26.1.5 flag handling](https://github.com/docker/cli/blob/v26.1.5/cli/flags/options.go),
[its TLS material loading](https://github.com/docker/cli/blob/v26.1.5/cli/context/tlsdata.go)
and [verified endpoint loading](https://github.com/docker/cli/blob/v26.1.5/cli/context/docker/load.go).
The Go [ConnectionState contract](https://pkg.go.dev/crypto/tls#ConnectionState)
identifies the last certificate in each verified chain as its trust anchor.
