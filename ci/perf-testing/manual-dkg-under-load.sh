#!/usr/bin/env bash
#=============================================================================
# manual-dkg-under-load.sh
#
# Ad-hoc load scenario: run a sustained decryption rate-flow CONCURRENTLY with a
# real DKG (preproc-key-gen -> key-gen, the heavy MPC preprocessing) to see
# whether the 13-party cluster sustains decryption while doing a DKG.
#
# WHERE TO RUN THIS:
#   Inside the deployed core-client pod, e.g.
#     kubectl exec -it -n kms-ci kms-core-client-0 -- bash
#     # copy this file in first, or paste it, then:
#     bash manual-dkg-under-load.sh
#
#   To capture the 13 core-pod logs at the same time, run the companion
#   ci/perf-testing/manual-capture-core-logs.sh from your laptop (it needs
#   kubectl, which the pod does not have). Start it BEFORE this script.
#
# See ../../manual-13-party-enclave-cluster.md for the full walkthrough.
#
# Tunables (override via env), e.g.:
#   PREPROC_WARMUP=1800 DECRYPT_PER_MIN=100 bash manual-dkg-under-load.sh
#   KEY_ID=<existing-key> bash manual-dkg-under-load.sh   # skip key minting
#=============================================================================

set -uo pipefail   # NOT -e: a failing decrypt chunk must not abort the whole run

#=============================================================================
# Configuration
#=============================================================================
CFG="${CFG:-/app/kms-core-client/config.toml}"   # rendered 13-core config in the pod
RUN="${RUN:-dkg-under-load-$(date +%Y%m%d-%H%M%S)}"
LOG_DIR="${LOG_DIR:-/tmp}"

# Let the DKG preprocessing run ALONE for this long before any decrypts start,
# so the cluster is deep into the heavy phase when the decrypt probe begins.
PREPROC_WARMUP="${PREPROC_WARMUP:-1800}"   # seconds of DKG-only before decrypts (default 30 min)
# Light decrypt probe: a trickle of single decrypts, not a saturation blast.
DECRYPT_PER_MIN="${DECRYPT_PER_MIN:-100}"  # decrypt launch cadence, requests/minute
DATA_TYPE="${DATA_TYPE:-euint64}"
TO_ENCRYPT="${TO_ENCRYPT:-ffffffffffffffff}"
DECRYPT_CMD="${DECRYPT_CMD:-public-decrypt}"   # or: user-decrypt
MAX_ITER="${MAX_ITER:-2880}"
# How often the core-client polls for the DKG preproc/keygen result, in ms,
# via KMS_CLIENT_POLL_INTERVAL_MS. Default 10s keeps core-side poll logs/load
# light during the (multi-hour) DKG. Applied ONLY to the DKG step — the decrypt
# trickle keeps the client's 500ms default so its latency isn't distorted.
# NOTE: needs a core-client image that reads KMS_CLIENT_POLL_INTERVAL_MS;
# on older images the var is simply ignored (polling stays at 500ms).
# --max-iter is a retry COUNT, so at 10s the default 2880 => ~8h timeout, which
# is intentionally left generous for a real multi-hour preproc.
DKG_POLL_INTERVAL_MS="${DKG_POLL_INTERVAL_MS:-10000}"
# A/B mode: run ONLY `preproc-key-gen` (the heavy TripleGen/BitGen phase) with
# timing — no key mint, no key-gen, no decrypt. This is the clean workload to
# run identically on the enclave and non-enclave envs to compare preproc speed.
PREPROC_ONLY="${PREPROC_ONLY:-0}"

# Client tracing (--logs): heavy tracing skews throughput, so default it ON for
# the DKG (we want to see what it's doing) and OFF for the decrypt loop (clean
# capacity numbers). The metrics JSON line is printed either way.
DKG_LOGS="${DKG_LOGS:-1}"
DECRYPT_LOGS="${DECRYPT_LOGS:-0}"

KEY_ID="${KEY_ID:-}"        # if set, Step 1 (key minting) is skipped

#=============================================================================
# Helpers
#=============================================================================
say()  { echo "[$(date -u +%H:%M:%S)] $*"; }
rule() { echo "============================================================"; }

# Extract the last "request_id": "..." printed by a kms-core-client run.
rid() { grep -o '"request_id": "[^"]*"' "$1" | tail -1 | sed 's/.*"\([^"]*\)"$/\1/'; }

dkg_logflag()     { [ "${DKG_LOGS}" = "1" ] && echo "--logs" || true; }
decrypt_logflag() { [ "${DECRYPT_LOGS}" = "1" ] && echo "--logs" || true; }

#=============================================================================
# Banner
#=============================================================================
rule
say "manual-dkg-under-load — decryption load while a full DKG runs"
rule
say "config file       : ${CFG}"
say "run tag           : ${RUN}"
say "log dir           : ${LOG_DIR}"
say "decrypt command   : ${DECRYPT_CMD} from-args (single-shot trickle)"
say "preproc warm-up   : ${PREPROC_WARMUP}s DKG-only before decrypts start"
say "decrypt cadence   : ~${DECRYPT_PER_MIN} req/min"
say "DKG poll interval : ${DKG_POLL_INTERVAL_MS}ms (decrypt keeps client 500ms default)"
say "decrypt payload   : -d ${DATA_TYPE} -e ${TO_ENCRYPT}"
say "client --logs     : DKG=${DKG_LOGS} decrypt=${DECRYPT_LOGS}"
say "pre-supplied key  : ${KEY_ID:-<none, will mint one>}"
rule

if [ ! -f "${CFG}" ]; then
  say "ERROR: config file ${CFG} not found. Are you running inside the core-client pod?"
  exit 1
fi

#=============================================================================
# A/B mode — run ONLY the heavy preprocessing, timed. Nothing else.
#=============================================================================
if [ "${PREPROC_ONLY}" = "1" ]; then
  export KMS_CLIENT_POLL_INTERVAL_MS="${DKG_POLL_INTERVAL_MS}"
  rule
  say "PREPROC-ONLY mode: running only preproc-key-gen (no key mint, no key-gen, no decrypt)"
  say "poll interval ${DKG_POLL_INTERVAL_MS}ms; fhe params come from ${CFG}"
  say "watch the cores separately with manual-metrics-watch.sh"
  rule
  po_log="${LOG_DIR}/${RUN}-preproc-only.log"
  start="$(date +%s)"
  kms-core-client $(dkg_logflag) --max-iter "${MAX_ITER}" -f "${CFG}" \
    preproc-key-gen 2>&1 | tee "${po_log}"
  rc="${PIPESTATUS[0]}"
  dur=$(( $(date +%s) - start ))
  preproc_id="$(rid "${po_log}")"
  rule
  say "PREPROC-ONLY done: rc=${rc}  duration=${dur}s (~$((dur / 60))m)  request_id=${preproc_id:-<none>}"
  say "log: ${po_log}"
  say "record this duration for the enclave-vs-non-enclave comparison."
  rule
  printf '%s\n' "${rc}" > "${LOG_DIR}/${RUN}-exit-code"
  exit "${rc}"
fi

#=============================================================================
# Step 1 — mint a decryption key the cheap way (insecure / dummy preprocessing)
#          (skipped if KEY_ID was supplied)
#=============================================================================
if [ -z "${KEY_ID}" ]; then
  rule; say "STEP 1: minting decryption key via the INSECURE path (no full preprocessing)"; rule

  say "1a) insecure-preproc-key-gen (dummy preprocessing) ..."
  kms-core-client $(dkg_logflag) --max-iter "${MAX_ITER}" -f "${CFG}" \
    insecure-preproc-key-gen 2>&1 | tee "${LOG_DIR}/${RUN}-udec-preproc.log"
  UDEC_PREPROC_ID="$(rid "${LOG_DIR}/${RUN}-udec-preproc.log")"
  if [ -z "${UDEC_PREPROC_ID}" ]; then
    say "ERROR: could not read a request_id from insecure-preproc-key-gen; aborting."
    exit 1
  fi
  say "1a) done. preproc id = ${UDEC_PREPROC_ID}"

  say "1b) insecure-key-gen -i ${UDEC_PREPROC_ID} ..."
  kms-core-client $(dkg_logflag) --max-iter "${MAX_ITER}" -f "${CFG}" \
    insecure-key-gen -i "${UDEC_PREPROC_ID}" 2>&1 | tee "${LOG_DIR}/${RUN}-udec-keygen.log"
  KEY_ID="$(rid "${LOG_DIR}/${RUN}-udec-keygen.log")"
  if [ -z "${KEY_ID}" ]; then
    say "ERROR: could not read a key id (request_id) from insecure-key-gen; aborting."
    exit 1
  fi
  say "1b) done. KEY_ID = ${KEY_ID}"
else
  say "STEP 1: skipped — using pre-supplied KEY_ID = ${KEY_ID}"
fi
rule; say "decryption key ready: KEY_ID=${KEY_ID}"; rule

#=============================================================================
# Step 2 — launch the DKG in the background (real preprocessing + keygen)
#=============================================================================
rule; say "STEP 2: starting FULL DKG in the background (preproc-key-gen -> key-gen)"; rule
(
  # Gentler result-polling for the long DKG only (decrypt trickle keeps default).
  export KMS_CLIENT_POLL_INTERVAL_MS="${DKG_POLL_INTERVAL_MS}"
  say "[dkg] preproc-key-gen (real preprocessing — heavy MPC phase; polling every ${DKG_POLL_INTERVAL_MS}ms) ..."
  kms-core-client $(dkg_logflag) --max-iter "${MAX_ITER}" -f "${CFG}" \
    preproc-key-gen 2>&1 | tee "${LOG_DIR}/${RUN}-dkg-preproc.log"
  PREPROC_ID="$(rid "${LOG_DIR}/${RUN}-dkg-preproc.log")"
  if [ -z "${PREPROC_ID}" ]; then
    say "[dkg] ERROR: no preproc request_id; DKG cannot continue to key-gen."
    exit 1
  fi
  say "[dkg] preproc done, id=${PREPROC_ID}; starting key-gen ..."
  kms-core-client $(dkg_logflag) --max-iter "${MAX_ITER}" -f "${CFG}" \
    key-gen -i "${PREPROC_ID}" 2>&1 | tee "${LOG_DIR}/${RUN}-dkg-keygen.log"
  say "[dkg] DKG COMPLETE"
) &
DKG_PID=$!
say "STEP 2: DKG running as background pid ${DKG_PID}"

#=============================================================================
# Step 3a — warm-up: let the DKG run ALONE before any decrypts
#=============================================================================
rule; say "STEP 3a: warm-up — DKG runs alone for ${PREPROC_WARMUP}s before decrypts start"; rule
warm_deadline=$(( $(date +%s) + PREPROC_WARMUP ))
while [ "$(date +%s)" -lt "${warm_deadline}" ]; do
  if ! kill -0 "${DKG_PID}" 2>/dev/null; then
    say "[warmup] DKG finished during warm-up — nothing to load against; skipping decrypts."
    break
  fi
  remaining=$(( warm_deadline - $(date +%s) ))
  say "[warmup] DKG still running; ${remaining}s left before decrypts start"
  sleep 60
done

#=============================================================================
# Step 3b — light decrypt trickle (~DECRYPT_PER_MIN/min) until the DKG exits
#=============================================================================
# Single-shot decrypts spaced by INTERVAL seconds. This is a launch cadence:
# if a decrypt takes longer than INTERVAL (likely while preproc hammers the
# cluster), the effective rate self-throttles below the target — which is fine
# for a gentle "does decrypt still work, and how slow is it?" probe.
# DECRYPT_PER_MIN<=0 (or non-numeric) => no decrypt noise, just wait on the DKG.
# Guard BEFORE the awk divide, otherwise 60/0 aborts the run with
# "awk: Division by zero" exactly when step 3b starts.
if awk "BEGIN{exit !((${DECRYPT_PER_MIN:-0}) > 0)}" 2>/dev/null; then
  INTERVAL="$(awk "BEGIN{printf \"%.3f\", 60/${DECRYPT_PER_MIN}}")"
else
  INTERVAL=""
  say "DECRYPT_PER_MIN=${DECRYPT_PER_MIN} -> decrypt trickle DISABLED; just waiting on the DKG."
fi
trickle_log="${LOG_DIR}/${RUN}-decrypt-trickle.log"
: > "${trickle_log}"
decrypt_n=0; decrypt_ok=0; decrypt_fail=0

if [ -n "${INTERVAL}" ] && kill -0 "${DKG_PID}" 2>/dev/null; then
  rule; say "STEP 3b: decrypt trickle ~${DECRYPT_PER_MIN}/min (interval ${INTERVAL}s) while the DKG runs"; rule
fi
while [ -n "${INTERVAL}" ] && kill -0 "${DKG_PID}" 2>/dev/null; do
  decrypt_n=$((decrypt_n + 1))
  start="$(date +%s.%N)"
  out="$(kms-core-client $(decrypt_logflag) --max-iter "${MAX_ITER}" -f "${CFG}" \
          "${DECRYPT_CMD}" from-args \
            -d "${DATA_TYPE}" -k "${KEY_ID}" -e "${TO_ENCRYPT}" --batch-size 1 2>&1)"
  rc=$?
  dur="$(awk "BEGIN{printf \"%.2f\", $(date +%s.%N)-${start}}")"
  {
    echo "=== decrypt #${decrypt_n} @ $(date -u +%H:%M:%S) rc=${rc} dur=${dur}s ==="
    echo "${out}"
  } >> "${trickle_log}"
  if [ "${rc}" -eq 0 ]; then
    decrypt_ok=$((decrypt_ok + 1)); state=ok
  else
    decrypt_fail=$((decrypt_fail + 1)); state=FAIL
  fi
  say "[decrypt] #${decrypt_n} ${state} in ${dur}s (ok=${decrypt_ok} fail=${decrypt_fail})"
  sleep "${INTERVAL}"
done

say "STEP 3: DKG background pid ${DKG_PID} has exited; stopping decrypt trickle."
wait "${DKG_PID}"
DKG_RC=$?

#=============================================================================
# Summary
#=============================================================================
rule
say "RUN COMPLETE — tag ${RUN}"
say "DKG exit code     : ${DKG_RC} ($([ "${DKG_RC}" -eq 0 ] && echo OK || echo FAILED))"
say "decrypts issued    : ${decrypt_n} (ok=${decrypt_ok}, fail=${decrypt_fail}) after ${PREPROC_WARMUP}s warm-up"
say "logs (in this pod) : ${LOG_DIR}/${RUN}-*.log (per-request detail in ${RUN}-decrypt-trickle.log)"
say ""
say "Pull them to your laptop with:"
say "  kubectl cp kms-ci/kms-core-client-0:${LOG_DIR} ./${RUN}/client-logs"
say "Core-pod logs were captured separately by manual-capture-core-logs.sh (Terminal B)."
rule
