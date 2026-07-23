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

Operators need the public key to turn on verification.

- Paste it into the `README.md` (or a dedicated `SIGNING_KEY.txt` in the repo)
  so it ships with the source and docs.
- Also publish it on the hub wiki / release notes page.

Operators configure:

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

The hub's `scripts/release/generate-agent-manifest.sh` now looks for a
`labtether-agent-<suffix>-<version>.sig` asset in the agent release and
includes the contents as a `signature` field under each
`agents.labtether-agent.binaries.<platform>` entry in `agent-manifest.json`.

`GET /api/v1/agent/releases/latest` surfaces the signature to agents. No
hub-side verification is performed (and none is needed — the agent is the
ultimate verifier). If an agent release ships without a signature, the
manifest simply omits the field and agents configured with a trusted public
key will refuse the update.

## Key Rotation

To rotate:

1. Generate a new keypair locally.
2. Update the local maintainer secret store.
3. Publish both the old and new public keys during the transition window.
4. Tag a new release. Only this release is signed by the new key.
5. Once all deployments have updated their
   `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` to the new key, drop the old
   one from published docs.

The agent currently accepts exactly one trusted public key. If you need a
rotation period where two keys are simultaneously trusted, emit two
signatures per release and update the agent to try each trusted key in turn
- a small enhancement not yet implemented.
