#!/usr/bin/env bash
# Proves test-workflow-policy.sh rejects each way the release signing key could
# leak past sign-release.yml: another workflow, an automatic trigger, a write
# permission, a release upload, the key in the build job, or the sign job
# running code from the tag. The release-host-proof.yml cases prove it may not
# use a secret, start on its own, write outside its stage job, edit a release,
# run repository code with the write token, or build its tool from elsewhere.
# Each case changes one line in a copy.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
POLICY="${SCRIPT_DIR}/test-workflow-policy.sh"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

fixture() {
  local dir="${WORK_DIR}/$1"
  mkdir -p "${dir}/.github" "${dir}/scripts/release" "${dir}/docs"
  cp -R "${ROOT_DIR}/.github/workflows" "${dir}/.github/workflows"
  cp "${ROOT_DIR}/scripts/release/sign-release.go" "${dir}/scripts/release/"
  cp "${ROOT_DIR}/docs/RELEASE_SIGNING.md" "${dir}/docs/"
  printf '%s\n' "${dir}"
}

expect_fail() {
  local name="$1" message="$2" file="$3" perl_expr="$4" dir output
  dir="$(fixture "${name}")"
  perl -0pi -e "${perl_expr}" "${dir}/${file}"
  if output="$(bash "${POLICY}" "${dir}" 2>&1)"; then
    printf 'policy case %s: passed, want failure\n' "${name}" >&2
    exit 1
  fi
  if [[ "${output}" != *"${message}"* ]]; then
    printf 'policy case %s: wrong failure: %s\n' "${name}" "${output}" >&2
    exit 1
  fi
}

bash "${POLICY}" "$(fixture unchanged)" >/dev/null

expect_fail other-workflow 'only sign-release.yml may use' .github/workflows/ci.yml \
  '$_ .= "      - run: echo \"\${{ secrets.RELEASE_SIGNING_PRIVATE_KEY }}\"\n"'
expect_fail push-trigger 'started only by workflow_dispatch' .github/workflows/sign-release.yml \
  's/^on:\n/on:\n  push:\n/m'
expect_fail write-permission 'may not request write permissions' .github/workflows/sign-release.yml \
  's/^  contents: read$/  contents: write/m'
expect_fail release-upload 'may not create releases' .github/workflows/sign-release.yml \
  '$_ .= "      - run: gh release upload \"\$TAG\" agent-signatures/*\n"'
expect_fail build-job-secret 'build job must not reference secrets' .github/workflows/sign-release.yml \
  's/(        id: build\n        env:\n)/$1          LEAK: \$\{\{ secrets.RELEASE_SIGNING_PRIVATE_KEY \}\}\n/'
expect_fail sign-job-tag-checkout 'sign job may use only the trusted commit' .github/workflows/sign-release.yml \
  's/ref: \$\{\{ github\.sha \}\}/ref: refs\/tags\/\$\{\{ inputs.tag \}\}/'

P=.github/workflows/release-host-proof.yml
expect_fail proof-secret 'release-host-proof.yml may not use secrets' "${P}" \
  '$_ .= "      - run: echo \"\${{ secrets.GITHUB_TOKEN }}\"\n"'
expect_fail proof-push-trigger 'release-host-proof.yml must be started only by workflow_dispatch' "${P}" \
  's/^on:\n/on:\n  push:\n/m'
expect_fail proof-job-write 'only contents: write, only in its stage job' "${P}" \
  's/(  linux-proof:\n)/$1    permissions:\n      contents: write\n/'
expect_fail proof-release-edit 'release-host-proof.yml may only download release assets' "${P}" \
  '$_ .= "      - run: gh release edit \"\$TAG\" --draft=false\n"'
expect_fail proof-stage-checkout 'stage job may not run repository code' "${P}" \
  's/(    steps:\n      - name: Validate inputs)/    steps:\n      - uses: actions\/checkout\@v7\n      - name: Validate inputs/'
expect_fail proof-branch-checkout 'proof jobs may check out only the trusted commit and the tag' "${P}" \
  's/ref: \$\{\{ github\.sha \}\}/ref: main/'

printf 'release workflow policy cases: PASS\n'
