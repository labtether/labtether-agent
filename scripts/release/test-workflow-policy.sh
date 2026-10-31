#!/usr/bin/env bash
set -Eeuo pipefail

# Optional first argument: repository root to check (used by the policy cases).
ROOT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WORKFLOW_DIR="${ROOT_DIR}/.github/workflows"
BINARY_WORKFLOW="${WORKFLOW_DIR}/release.yml"
CONTAINER_WORKFLOW="${WORKFLOW_DIR}/container-release.yml"
SIGNING_WORKFLOW="${WORKFLOW_DIR}/sign-release.yml"
SIGNER="${ROOT_DIR}/scripts/release/sign-release.go"
SIGNING_DOC="${ROOT_DIR}/docs/RELEASE_SIGNING.md"

fail() {
  printf 'release workflow policy: %s\n' "$*" >&2
  exit 1
}

for workflow in "${BINARY_WORKFLOW}" "${CONTAINER_WORKFLOW}" "${SIGNING_WORKFLOW}"; do
  [[ -f "${workflow}" && ! -L "${workflow}" ]] ||
    fail "expected regular workflow file: ${workflow##*/}"
done
for local_file in "${SIGNER}" "${SIGNING_DOC}"; do
  [[ -f "${local_file}" && ! -L "${local_file}" ]] ||
    fail "expected regular local release file: ${local_file##*/}"
done

if grep -Eq \
  'RELEASE_SIGNING_PRIVATE_KEY|secrets\.|softprops/action-gh-release|actions/upload-artifact|gh[[:space:]]+release|subject-path:' \
  "${BINARY_WORKFLOW}" "${CONTAINER_WORKFLOW}"; then
  fail "hosted release workflows contain a forbidden secret or binary publication path"
fi

if grep -Eq 'contents:[[:space:]]*write' "${BINARY_WORKFLOW}" "${CONTAINER_WORKFLOW}"; then
  fail "hosted release workflows may not write GitHub repository contents"
fi

if grep -Eq \
  'packages:[[:space:]]*write|attestations:[[:space:]]*write|artifact-metadata:[[:space:]]*write|id-token:[[:space:]]*write' \
  "${BINARY_WORKFLOW}"; then
  fail "binary source-verification workflow has write-capable permissions"
fi

grep -Fq 'contents: read' "${BINARY_WORKFLOW}" ||
  fail "binary source-verification workflow lacks explicit read-only contents permission"
grep -Fq 'Compile source without publishing artifacts' "${BINARY_WORKFLOW}" ||
  fail "binary workflow no longer documents its non-publication boundary"
grep -Fq '${{ github.token }}' "${CONTAINER_WORKFLOW}" ||
  fail "container workflow must use only the ephemeral GitHub token"
grep -Fq 'packages: write' "${CONTAINER_WORKFLOW}" ||
  fail "container workflow lacks its narrowly scoped GHCR permission"
grep -Fq 'subject-digest:' "${CONTAINER_WORKFLOW}" ||
  fail "container provenance must bind the pushed image digest"
if grep -Fq 'APP_VERSION=' "${CONTAINER_WORKFLOW}"; then
  fail "container workflow uses the wrong Docker build argument"
fi
grep -Eq '^[[:space:]]+VERSION=\$\{\{ github\.ref_name \}\}$' "${CONTAINER_WORKFLOW}" ||
  fail "container workflow does not inject the release version into the Docker build"
grep -Fq 'confirm-sign' "${SIGNER}" ||
  fail "local signer lacks an exact confirmation flag"
grep -Fq 'signing requires exact --confirm-sign TAG confirmation' "${SIGNER}" ||
  fail "local signer lacks exact tag confirmation enforcement"
grep -Fq -- '--confirm-sign vX.Y.Z' "${SIGNING_DOC}" ||
  fail "release signing doc does not document the local signing confirmation"

# The release signing key may reach exactly one workflow: sign-release.yml,
# started by hand, read-only, returning a short-lived artifact and nothing else.
for workflow in "${WORKFLOW_DIR}"/*; do
  [[ "${workflow}" == "${SIGNING_WORKFLOW}" ]] && continue
  if [[ -f "${workflow}" ]] &&
    grep -Eq 'RELEASE_SIGNING_PRIVATE_KEY|toJSON\(secrets\)|secrets\[|secrets:[[:space:]]*inherit' "${workflow}"; then
    fail "only sign-release.yml may use RELEASE_SIGNING_PRIVATE_KEY, found in ${workflow##*/}"
  fi
done

if [[ "$(grep -Ec "^([\"']?on[\"']?|true)[[:space:]]*:" "${SIGNING_WORKFLOW}")" != 1 ]] ||
  ! grep -Eq '^on:[[:space:]]*$' "${SIGNING_WORKFLOW}"; then
  fail "sign-release.yml must declare its triggers in one block"
fi
signing_triggers="$(awk '
  /^on:[[:space:]]*$/ { in_on = 1; next }
  in_on && /^[^[:space:]#]/ { in_on = 0 }
  in_on && /^  [^[:space:]#]/ { key = $1; sub(/:.*$/, "", key); gsub(/["\047]/, "", key); print key }
' "${SIGNING_WORKFLOW}")"
[[ "${signing_triggers}" == "workflow_dispatch" ]] ||
  fail "sign-release.yml must be started only by workflow_dispatch"

if grep -Eq '^[[:space:]]*[A-Za-z-]+:[[:space:]]*write[[:space:]]*(#.*)?$|write-all' "${SIGNING_WORKFLOW}"; then
  fail "sign-release.yml may not request write permissions"
fi
if ! grep -Eq '^permissions:[[:space:]]*$' "${SIGNING_WORKFLOW}" ||
  ! grep -Fxq '  contents: read' "${SIGNING_WORKFLOW}"; then
  fail "sign-release.yml lacks explicit read-only contents permission"
fi

if grep -Eq \
  'softprops/action-gh-release|actions/create-release|release-action|upload-release|gh[[:space:]]+(release|api)|/releases|git[[:space:]]+(push|tag)|actions/attest|docker/|curl|wget' \
  "${SIGNING_WORKFLOW}"; then
  fail "sign-release.yml may not create releases, tags or other uploads"
fi
[[ "$(grep -c 'actions/upload-artifact@' "${SIGNING_WORKFLOW}")" == 1 ]] ||
  fail "sign-release.yml must upload exactly one workflow artifact"
grep -Eq '^[[:space:]]+retention-days:[[:space:]]*1[[:space:]]*$' "${SIGNING_WORKFLOW}" ||
  fail "sign-release.yml artifact must expire after one day"

[[ "$(grep -o 'secrets[^[:space:]}]*' "${SIGNING_WORKFLOW}")" == 'secrets.RELEASE_SIGNING_PRIVATE_KEY' ]] ||
  fail "sign-release.yml must reference only RELEASE_SIGNING_PRIVATE_KEY, exactly once"
if grep -Eq '(^|[[:space:]])(set|bash)[[:space:]]+-[A-Za-z]*x|xtrace' "${SIGNING_WORKFLOW}"; then
  fail "sign-release.yml may not trace shell commands"
fi
grep -Fq 'unset RELEASE_SIGNING_PRIVATE_KEY' "${SIGNING_WORKFLOW}" ||
  fail "sign-release.yml must unset the key variable after reading it"
grep -Fq -- '--confirm-sign "${TAG}"' "${SIGNING_WORKFLOW}" ||
  fail "sign-release.yml must pass the exact tag confirmation to the signer"

printf 'release workflow policy: PASS\n'
