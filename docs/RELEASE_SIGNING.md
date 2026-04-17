# Release signing — one-time setup

`labtether-agent` self-update verifies an ed25519 signature over the canonical
release metadata (`version\nos\narch\nsha256\nsize`). Once signing is active,
operators can set `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` to the matching
public key and the agent will fail any update that was not signed with the
paired private key.

This doc covers the one-time key generation and repository/hub wiring. It is
intended for the release maintainer, not for end operators.

## 1. Generate the keypair

Any machine with Go installed:

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
	fmt.Println("private (store as GitHub secret):", base64.StdEncoding.EncodeToString(priv))
}
EOF
```

The private key is a 64-byte ed25519 private key (seed + derived public half);
the signer accepts either a 32-byte seed or the 64-byte expanded form.

## 2. Store the private key in CI

In the `labtether/labtether-agent` repo settings → **Secrets and variables** →
**Actions** → **New repository secret**:

- **Name:** `RELEASE_SIGNING_PRIVATE_KEY`
- **Value:** the base64 private-key string from step 1

Once this secret is set, the "Sign release metadata" step in
`.github/workflows/release.yml` will run on every tag push, producing
`*.sig` and `*.metadata.json` assets alongside each platform binary.

## 3. Publish the public key

Operators need the public key to turn on verification:

- Paste it into the `README.md` (or a dedicated `SIGNING_KEY.txt` in the repo)
  so it ships with the source and docs.
- Also publish it on the hub wiki / release notes page.

Operators configure:

```sh
export LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY="<base64 public key>"
```

With that set and the signature present in the manifest, the agent enforces
signature verification on every self-update.

## 4. Hub-side wiring

The hub's `scripts/release/generate-agent-manifest.sh` now looks for a
`labtether-agent-<suffix>-<version>.sig` asset in the agent release and
includes the contents as a `signature` field under each
`agents.labtether-agent.binaries.<platform>` entry in `agent-manifest.json`.

`GET /api/v1/agent/releases/latest` surfaces the signature to agents. No
hub-side verification is performed (and none is needed — the agent is the
ultimate verifier). If an agent release ships without a signature, the
manifest simply omits the field and agents configured with a trusted public
key will refuse the update.

## 5. Key rotation

To rotate:

1. Generate a new keypair (step 1).
2. Update `RELEASE_SIGNING_PRIVATE_KEY` in CI (step 2).
3. Publish both the old and new public keys during the transition window.
4. Tag a new release — only this release is signed by the new key.
5. Once all deployments have updated their
   `LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY` to the new key, drop the old
   one from published docs.

The agent currently accepts exactly one trusted public key. If you need a
rotation period where two keys are simultaneously trusted, emit two
signatures per release and update the agent to try each trusted key in turn
— a small enhancement not yet implemented.
