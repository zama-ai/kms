#!/usr/bin/env bash
# Classify the outcome of a consumer cell into a structured result.json.
#
# Args:
#   $1 producer version  (kms@A, the server side)
#   $2 consumer version  (node-tkms@B, the client side)
#   $3 exit code from `node --test tests/js`
#   $4 path to the captured log
#   $5 path to write result.json
#
# status is one of:
#   pass   exit == 0
#   fail   exit != 0 AND the log contains an assertion / decode / bincode
#          marker -- treat as a genuine cross-version incompatibility
#   error  exit != 0 with no such marker -- treat as a workflow-level failure
#          (toolchain problem, missing artifact, etc.)

set -euo pipefail

if [[ $# -lt 5 ]]; then
    echo "usage: $0 <producer> <consumer> <exit_code> <log_path> <result_path>" >&2
    exit 64
fi

PRODUCER="$1"
CONSUMER="$2"
EXIT_CODE="$3"
LOG_PATH="$4"
RESULT_PATH="$5"

status="pass"
if [[ "${EXIT_CODE}" != "0" ]]; then
    if [[ -f "${LOG_PATH}" ]] \
        && grep -E -q 'AssertionError|assert\.|bincode|DecodeError|deserialize|Unversion|panic|RuntimeError|tests/js/test\.js' "${LOG_PATH}"; then
        status="fail"
    else
        status="error"
    fi
fi

run_url=""
if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
    run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

log_excerpt=""
if [[ -f "${LOG_PATH}" ]]; then
    log_excerpt="$(head -c 8000 "${LOG_PATH}")"
fi

jq -n \
    --arg producer "${PRODUCER}" \
    --arg consumer "${CONSUMER}" \
    --arg status "${status}" \
    --argjson exit_code "${EXIT_CODE}" \
    --arg run_url "${run_url}" \
    --arg log_excerpt "${log_excerpt}" \
    '{producer: $producer, consumer: $consumer, status: $status, exit_code: $exit_code, run_url: $run_url, log_excerpt: $log_excerpt}' \
    > "${RESULT_PATH}"

echo "compat-matrix cell ${PRODUCER} -> ${CONSUMER}: ${status} (exit ${EXIT_CODE})"
