#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY_WORKFLOW="${ROOT_DIR}/.github/workflows/release.yml"
CONTAINER_WORKFLOW="${ROOT_DIR}/.github/workflows/container-release.yml"
SIGNER="${ROOT_DIR}/scripts/release/sign-release.go"
SIGNING_DOC="${ROOT_DIR}/docs/RELEASE_SIGNING.md"

fail() {
  printf 'release workflow policy: %s\n' "$*" >&2
  exit 1
}

for workflow in "${BINARY_WORKFLOW}" "${CONTAINER_WORKFLOW}"; do
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
grep -Fq 'confirm-sign' "${SIGNER}" ||
  fail "local signer lacks an exact confirmation flag"
grep -Fq 'signing requires exact --confirm-sign TAG confirmation' "${SIGNER}" ||
  fail "local signer lacks exact tag confirmation enforcement"
grep -Fq -- '--confirm-sign vX.Y.Z' "${SIGNING_DOC}" ||
  fail "release signing doc does not document the local signing confirmation"

printf 'release workflow policy: PASS\n'
