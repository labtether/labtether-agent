#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST_FILE="${ROOT_DIR}/security/gosec_allowlist.tsv"

if [[ ! -f "${ALLOWLIST_FILE}" ]]; then
  echo "missing allowlist: ${ALLOWLIST_FILE}" >&2
  exit 1
fi

if ! command -v gosec >/dev/null 2>&1; then
  echo "gosec not found in PATH" >&2
  exit 1
fi

tmp_json="$(mktemp)"
tmp_current="$(mktemp)"
tmp_allowlisted="$(mktemp)"
cleanup() {
  rm -f "${tmp_json}" "${tmp_current}" "${tmp_allowlisted}"
}
trap cleanup EXIT

(
  cd "${ROOT_DIR}"
  gosec -fmt=json ./... >"${tmp_json}" 2>/dev/null || true
)

if ! jq -e '.' "${tmp_json}" >/dev/null 2>&1; then
  echo "gosec check failed: scanner did not produce valid JSON output" >&2
  exit 1
fi

jq -r --arg prefix "${ROOT_DIR}/" '
  .Issues[]? | [.rule_id, (.file | sub("^" + $prefix; "")), (.line | tostring)] | @tsv
' "${tmp_json}" | LC_ALL=C sort -u >"${tmp_current}"

awk -F '\t' '
  BEGIN { OFS = "\t" }
  /^#/ { next }
  NF < 4 { next }
  { print $1, $2, $3 }
' "${ALLOWLIST_FILE}" | LC_ALL=C sort -u >"${tmp_allowlisted}"

unapproved="$(comm -23 "${tmp_current}" "${tmp_allowlisted}" || true)"
stale="$(comm -13 "${tmp_current}" "${tmp_allowlisted}" || true)"

if [[ -n "${unapproved}" ]]; then
  echo "gosec check failed: unallowlisted findings detected" >&2
  echo "${unapproved}" >&2
  exit 1
fi

if [[ -n "${stale}" ]]; then
  echo "gosec check failed: stale allowlist entries detected" >&2
  echo "${stale}" >&2
  exit 1
fi

finding_count="$(wc -l <"${tmp_current}" | tr -d '[:space:]')"
echo "gosec allowlist check passed (${finding_count} reviewed findings)."
