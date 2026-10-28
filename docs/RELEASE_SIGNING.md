# Release Signing

`labtether-agent` self-update verifies an ed25519 signature over the canonical
release metadata (`version\nos\narch\nsha256\nsize`). Once signing is active,
operators can set `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` to the matching
public key and the agent will fail any update that was not signed with the
paired private key.

This doc covers local-only key handling and the maintainer release flow. GitHub
Actions does not receive the private key, does not publish release binaries,
and does not upload signed assets. Hosted workflows only verify tagged source
and publish the container image.

## Keypair

Generate the keypair on a trusted local machine:

```sh
go run - <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Println("public  (publish to operators):", base64.StdEncoding.EncodeToString(pub))
	fmt.Println("private (store locally only):", base64.StdEncoding.EncodeToString(priv))
}
EOF
```

The private key is a 64-byte ed25519 private key (seed + derived public half);
the signer accepts either a 32-byte seed or the 64-byte expanded form.

Store the private key only in the maintainer's local secret store. Do not add it
to GitHub Actions secrets, repository files, release artifacts, logs, caches, or
temporary directories inside a source checkout.

## Public Key

Self-update refuses to run until a trusted public key is configured (or the
operator sets `LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED=true`). The key is
published in three places that must stay identical:

- `scripts/release/agent-release-public-key.b64` in this repository (the
  release contract verifies signatures with it);
- `scripts/release/agent-release-public-key.b64` in the Hub repository, which
  the Hub's install command uses to set the key on new agents;
- the `README.md` "Release signing" section and its manual verification steps.

Operators who install by hand configure:

```sh
export LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY="<base64 public key>"
```

With that set and the signature present in the manifest, the agent enforces
signature verification on every self-update.

## Local Release Flow

The release has five separate local gates:

1. Build the four raw binaries from a clean, exact-tagged source checkout.
2. Run `go run ./scripts/release/release-contract prepare` to create checksums,
   deterministic Linux archives, and the immutable build record in an external
   private stage directory.
3. For each raw binary, pipe the local private key to
   `go run ./scripts/release/sign-release.go --confirm-sign vX.Y.Z` and write
   the matching `.sig` and `.metadata.json` files into the stage assets
   directory. The confirmation value must exactly match the release tag.
4. Run `go run ./scripts/release/release-contract seal`, then verify the sealed
   manifest and host proofs on Linux and Windows.
5. Create a draft release, inspect its exact 20 assets, then publish only from a
   separate invocation that rechecks the fresh draft and the inspection receipt.

Build the raw binaries with `GOTOOLCHAIN=go1.27.3` and pass
`--go-version go1.27.3` to `release-contract prepare`. The prepare gate checks
each binary's embedded Go version and rejects older or unpinned builders.

Link the public key into each binary, the same way as the version:

```sh
update_key="$(tr -d '[:space:]' < scripts/release/agent-release-public-key.b64)"
go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.updatePublicKey=${update_key}" ./cmd/labtether-agent
```

An agent then verifies updates with this key even when
`LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` is unset. A key in that variable
replaces the built-in key. Neither can be bypassed with
`LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED`, which applies only to builds without a
linked key.

The public contract is exactly 20 release assets:

- four raw binaries: Linux amd64, Linux arm64, Windows amd64, Windows arm64
- four raw `.sha256` files
- four detached signatures named `<raw>-<tag>.sig`
- four metadata files named `<raw>-<tag>.metadata.json`
- two Linux tarballs
- two Linux tarball `.sha256` files

The local stage directory must be outside the repository, private to the current
user, and free of symlinks. Do not copy private keys into the stage; feed the
signer through stdin and let only the signed release outputs enter the stage.

## Hub Wiring

The Hub's `scripts/release/generate-agent-manifest.sh` requires the exact release
tag's Linux and Windows binaries, checksums, detached Ed25519 signatures and
metadata. It checks each binary's bytes and metadata against the pinned public
key before adding it to `agent-manifest.json` and the Hub image. Missing or
invalid assets stop manifest generation and coordinated Hub tagging.

Each `agents.labtether-agent.binaries.<platform>` entry includes the verified
signature. `GET /api/v1/agent/releases/latest` returns it to agents, which
check it again before self-update.

The standalone Windows amd64 and arm64 executables use this Ed25519 release
trust. This flow does not add Authenticode signatures or establish a Windows
publisher identity. The separate native Windows app's optional local eSigner
CKA flow signs its wrapper, bundled Go child and MSI. It does not sign these
standalone downloads or replace their Ed25519 checks.

## Key Rotation

To rotate:

1. Generate a new keypair locally.
2. Update the local maintainer secret store.
3. Publish both the old and new public keys during the transition window.
4. Tag a new release. Only this release is signed by the new key.
5. Once all deployments run a release with the new built-in key, or have
   updated their `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` to the new key,
   drop the old one from published docs.

The agent currently accepts exactly one trusted public key. If you need a
rotation period where two keys are simultaneously trusted, emit two
signatures per release and update the agent to try each trusted key in turn
- a small enhancement not yet implemented.
