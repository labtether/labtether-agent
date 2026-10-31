#!/usr/bin/env bash
set -Eeuo pipefail

# Optional first argument: repository root to check (used by the policy cases).
ROOT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WORKFLOW_DIR="${ROOT_DIR}/.github/workflows"
BINARY_WORKFLOW="${WORKFLOW_DIR}/release.yml"
CONTAINER_WORKFLOW="${WORKFLOW_DIR}/container-release.yml"
SIGNING_WORKFLOW="${WORKFLOW_DIR}/sign-release.yml"
PROOF_WORKFLOW="${WORKFLOW_DIR}/release-host-proof.yml"
SIGNER="${ROOT_DIR}/scripts/release/sign-release.go"
SIGNING_DOC="${ROOT_DIR}/docs/RELEASE_SIGNING.md"

fail() {
  printf 'release workflow policy: %s\n' "$*" >&2
  exit 1
}

# workflow_triggers FILE: the keys of a one-block top-level on: map.
workflow_triggers() {
  if [[ "$(grep -Ec "^([\"']?on[\"']?|true)[[:space:]]*:" "$1")" != 1 ]] ||
    ! grep -Eq '^on:[[:space:]]*$' "$1"; then
    printf 'split-on-block\n'
    return
  fi
  awk '
    /^on:[[:space:]]*$/ { in_on = 1; next }
    in_on && /^[^[:space:]#]/ { in_on = 0 }
    in_on && /^  [^[:space:]#]/ { key = $1; sub(/:.*$/, "", key); gsub(/["\047]/, "", key); print key }
  ' "$1"
}

# workflow_jobs FILE: job IDs in order, space-separated.
workflow_jobs() {
  awk '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    in_jobs && /^[^[:space:]#]/ { in_jobs = 0 }
    in_jobs && /^  [^[:space:]#]/ { key = $1; sub(/:.*$/, "", key); print key }
  ' "$1" | tr '\n' ' '
}

# workflow_job FILE JOB: the lines of one job.
workflow_job() {
  awk -v job="$2" '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    in_jobs && /^[^[:space:]#]/ { in_jobs = 0 }
    in_jobs && /^  [^[:space:]#]/ { current = $1; sub(/:.*$/, "", current) }
    in_jobs && current == job { print }
  ' "$1"
}

for workflow in "${BINARY_WORKFLOW}" "${CONTAINER_WORKFLOW}" "${SIGNING_WORKFLOW}" "${PROOF_WORKFLOW}"; do
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
# started by hand, read-only, returning short-lived artifacts and nothing else.
for workflow in "${WORKFLOW_DIR}"/*; do
  [[ "${workflow}" == "${SIGNING_WORKFLOW}" ]] && continue
  if [[ -f "${workflow}" ]] &&
    grep -Eq 'RELEASE_SIGNING_PRIVATE_KEY|toJSON\(secrets\)|secrets\[|secrets:[[:space:]]*inherit' "${workflow}"; then
    fail "only sign-release.yml may use RELEASE_SIGNING_PRIVATE_KEY, found in ${workflow##*/}"
  fi
done

signing_triggers="$(workflow_triggers "${SIGNING_WORKFLOW}")"
[[ "${signing_triggers}" != "split-on-block" ]] ||
  fail "sign-release.yml must declare its triggers in one block"
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
[[ "$(grep -c 'actions/upload-artifact@' "${SIGNING_WORKFLOW}")" == 2 ]] ||
  fail "sign-release.yml must upload exactly two workflow artifacts"
if [[ "$(grep -c 'retention-days:' "${SIGNING_WORKFLOW}")" != 2 ]] ||
  [[ "$(grep -Ec '^[[:space:]]+retention-days:[[:space:]]*1[[:space:]]*$' "${SIGNING_WORKFLOW}")" != 2 ]]; then
  fail "sign-release.yml artifacts must expire after one day"
fi

# Two jobs: build compiles the tag without the key; sign runs only code from
# the trusted workflow commit and the build job's binaries as data.
[[ "$(workflow_jobs "${SIGNING_WORKFLOW}")" == "build sign " ]] ||
  fail "sign-release.yml must have exactly a build job and a sign job"
build_job="$(workflow_job "${SIGNING_WORKFLOW}" build)"
sign_job="$(workflow_job "${SIGNING_WORKFLOW}" sign)"
if grep -q 'secrets' <<< "${build_job}"; then
  fail "sign-release.yml build job must not reference secrets"
fi
sign_sources="$(grep -E '^[[:space:]]+(ref|repository|run-id|github-token):' <<< "${sign_job}" || true)"
bad_sources="$(grep -Ev '^[[:space:]]+ref:[[:space:]]*\$\{\{ github\.sha \}\}[[:space:]]*$' <<< "${sign_sources}" || true)"
if [[ -n "${bad_sources//[[:space:]]/}" ]] ||
  grep -Eq 'cmd/labtether-agent|refs/tags|git[[:space:]]+(clone|fetch|checkout|archive)' <<< "${sign_job}"; then
  fail "sign-release.yml sign job may use only the trusted commit and this run's build"
fi
if ! grep -Eq '^[[:space:]]+path:[[:space:]]*trusted[[:space:]]*$' <<< "${sign_job}" ||
  ! grep -Eq '^[[:space:]]+working-directory:[[:space:]]*trusted[[:space:]]*$' <<< "${sign_job}" ||
  ! grep -Fq 'trusted/scripts/release/agent-release-public-key.b64' <<< "${sign_job}"; then
  fail "sign-release.yml sign job must build the signer and read the public key from the trusted checkout"
fi

[[ "$(grep -o 'secrets[^[:space:]}]*' "${SIGNING_WORKFLOW}")" == 'secrets.RELEASE_SIGNING_PRIVATE_KEY' ]] ||
  fail "sign-release.yml must reference only RELEASE_SIGNING_PRIVATE_KEY, exactly once"
if grep -Eq '(^|[[:space:]])(set|bash)[[:space:]]+-[A-Za-z]*x|xtrace' "${SIGNING_WORKFLOW}"; then
  fail "sign-release.yml may not trace shell commands"
fi
grep -Fq 'unset RELEASE_SIGNING_PRIVATE_KEY' "${SIGNING_WORKFLOW}" ||
  fail "sign-release.yml must unset the key variable after reading it"
grep -Fq -- '--confirm-sign "${TAG}"' "${SIGNING_WORKFLOW}" ||
  fail "sign-release.yml must pass the exact tag confirmation to the signer"

# release-host-proof.yml runs host-proof on a draft's assets on hosted Linux
# and Windows runners. It is started by hand, uses no secret and changes
# nothing. GitHub lists draft releases only to tokens with push access, so its
# stage job alone holds contents: write. That job runs no repository code and
# its only GitHub command is `gh release download`.
if grep -Eq 'secrets|toJSON\(|id-token' "${PROOF_WORKFLOW}"; then
  fail "release-host-proof.yml may not use secrets"
fi
[[ "$(workflow_triggers "${PROOF_WORKFLOW}")" == "workflow_dispatch" ]] ||
  fail "release-host-proof.yml must be started only by workflow_dispatch"
[[ "$(workflow_jobs "${PROOF_WORKFLOW}")" == "stage linux-proof windows-proof " ]] ||
  fail "release-host-proof.yml must have exactly stage, linux-proof and windows-proof jobs"
proof_stage="$(workflow_job "${PROOF_WORKFLOW}" stage)"
proof_writes="$(grep -E ':[[:space:]]*write([[:space:]]|$)|write-all' "${PROOF_WORKFLOW}" || true)"
if [[ "$(grep -c . <<< "${proof_writes}")" != 1 ]] ||
  ! grep -Eq '^      contents:[[:space:]]*write([[:space:]]+#.*)?$' <<< "${proof_writes}" ||
  ! grep -Fxq -- "${proof_writes}" <<< "${proof_stage}"; then
  fail "release-host-proof.yml may request only contents: write, only in its stage job"
fi
if ! grep -Eq '^permissions:[[:space:]]*$' "${PROOF_WORKFLOW}" ||
  ! grep -Fxq '  contents: read' "${PROOF_WORKFLOW}"; then
  fail "release-host-proof.yml lacks explicit read-only contents permission"
fi
stage_uses="$(grep -E '^[[:space:]]+(- )?uses:' <<< "${proof_stage}" || true)"
if grep -Ev 'uses:[[:space:]]*actions/upload-artifact@' <<< "${stage_uses}" | grep -q . ||
  grep -Eq 'working-directory|scripts/|(^|[[:space:]])(go|git|make|npm)[[:space:]]' <<< "${proof_stage}"; then
  fail "release-host-proof.yml stage job may not run repository code"
fi
proof_code="$(sed -E 's/(^|[[:space:]])#.*$//' "${PROOF_WORKFLOW}")"
proof_gh="$(grep -oE '(^|[^[:alnum:]_./-])gh[[:space:]]+[a-z-]+([[:space:]]+[a-z-]+)?' <<< "${proof_code}" |
  sed -E 's/^[^g]+//' | LC_ALL=C sort -u)"
if [[ "${proof_gh}" != "gh release download" ]] ||
  [[ "$(grep -c 'github\.token' "${PROOF_WORKFLOW}")" != 1 ]] ||
  ! grep -Fq 'GH_TOKEN: ${{ github.token }}' <<< "${proof_stage}" ||
  grep -Eq 'curl|wget|/releases|api\.github|git[[:space:]]+(push|tag)|softprops|create-release|upload-release|attest|docker/' <<< "${proof_code}"; then
  fail "release-host-proof.yml may only download release assets"
fi
if [[ "$(grep -c 'actions/upload-artifact@' "${PROOF_WORKFLOW}")" != 3 ]] ||
  [[ "$(grep -c 'retention-days:' "${PROOF_WORKFLOW}")" != 3 ]] ||
  [[ "$(grep -Ec '^[[:space:]]+retention-days:[[:space:]]*1[[:space:]]*$' "${PROOF_WORKFLOW}")" != 3 ]]; then
  fail "release-host-proof.yml must upload exactly three one-day artifacts"
fi
for job in linux-proof windows-proof; do
  proof_job="$(workflow_job "${PROOF_WORKFLOW}" "${job}")"
  proof_sources="$(grep -E '^[[:space:]]+(ref|repository|run-id|github-token):' <<< "${proof_job}" || true)"
  if grep -Ev '^[[:space:]]+ref:[[:space:]]*(\$\{\{ github\.sha \}\}|refs/tags/\$\{\{ inputs\.tag \}\})[[:space:]]*$' <<< "${proof_sources}" |
    grep -q . || grep -Eq 'permissions:|go[[:space:]]+run' <<< "${proof_job}"; then
    fail "release-host-proof.yml proof jobs may check out only the trusted commit and the tag"
  fi
  if ! grep -Eq '^[[:space:]]+working-directory:[[:space:]]*trusted[[:space:]]*$' <<< "${proof_job}" ||
    ! grep -Eq 'go build -mod=readonly -trimpath -o .* \./scripts/release/release-contract$' <<< "${proof_job}" ||
    ! grep -Fq -- '--repository-root' <<< "${proof_job}"; then
    fail "release-host-proof.yml proof jobs must build release-contract from the trusted checkout"
  fi
done
if grep -Eq '(^|[[:space:]])(set|bash)[[:space:]]+-[A-Za-z]*x|xtrace|Set-PSDebug' "${PROOF_WORKFLOW}"; then
  fail "release-host-proof.yml may not trace shell commands"
fi

printf 'release workflow policy: PASS\n'
